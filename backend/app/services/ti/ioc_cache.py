"""Redis IOC cache for fast Push Mode lookups."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.redis import get_redis
from app.services.ti.ioc_types import IOCRecord, IOCType

logger = logging.getLogger(__name__)


class IOCCache:
    """Redis-backed cache for IOC lookups."""

    KEY_PREFIX = "chad:ioc"
    # Reverse index: MISP attribute UUID -> IOC key, so false-positive eviction is
    # an O(1) lookup instead of a blocking KEYS scan + per-key GET over the whole
    # IOC keyspace (which stalls the single-threaded Redis shared by the ingest
    # hot path). Kept under a separate prefix so SCANs of KEY_PREFIX don't see it.
    ATTR_PREFIX = "chad:iocattr"

    def _make_key(self, ioc_type: IOCType, value: str) -> str:
        """Generate Redis key for an IOC."""
        return f"{self.KEY_PREFIX}:{ioc_type.value}:{value}"

    def _attr_key(self, attribute_uuid: str) -> str:
        """Redis key for the attribute-UUID -> IOC-key reverse index."""
        return f"{self.ATTR_PREFIX}:{attribute_uuid}"

    async def _scan_keys(self, redis, match: str) -> list[str]:
        """Collect keys matching a pattern using non-blocking SCAN (not KEYS)."""
        keys: list[str] = []
        cursor = 0
        while True:
            cursor, batch = await redis.scan(cursor, match=match, count=500)
            keys.extend(batch)
            if cursor == 0:
                break
        return keys

    async def store_ioc(self, record: IOCRecord) -> None:
        """Store a single IOC in Redis.

        Args:
            record: The IOC record to store.
        """
        redis = await get_redis()
        key = record.redis_key
        value = json.dumps(record.to_dict())

        # Calculate TTL in seconds
        ttl_seconds = None
        if record.expires_at:
            ttl_seconds = int((record.expires_at - datetime.now(UTC)).total_seconds())
            if ttl_seconds <= 0:
                # Already expired, don't store
                return

        await redis.set(key, value, ex=ttl_seconds)
        # Maintain the reverse index (same TTL so it expires with the IOC).
        if record.misp_attribute_uuid:
            await redis.set(self._attr_key(record.misp_attribute_uuid), key, ex=ttl_seconds)

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Look up a single IOC in Redis.

        Args:
            ioc_type: Type of IOC.
            value: IOC value to look up.

        Returns:
            IOC data dict if found, None otherwise.
        """
        redis = await get_redis()
        key = self._make_key(ioc_type, value)
        data = await redis.get(key)

        if data is None:
            return None

        return json.loads(data)

    async def bulk_store_iocs(self, records: list[IOCRecord]) -> int:
        """Store multiple IOCs efficiently using pipeline.

        Args:
            records: List of IOC records to store.

        Returns:
            Number of IOCs stored.
        """
        if not records:
            return 0

        redis = await get_redis()
        count = 0

        pipe = redis.pipeline()
        for record in records:
            value = json.dumps(record.to_dict())

            # Calculate TTL
            ttl_seconds = None
            if record.expires_at:
                ttl_seconds = int((record.expires_at - datetime.now(UTC)).total_seconds())
                if ttl_seconds <= 0:
                    continue

            pipe.set(record.redis_key, value, ex=ttl_seconds)
            if record.misp_attribute_uuid:
                pipe.set(self._attr_key(record.misp_attribute_uuid), record.redis_key, ex=ttl_seconds)
            count += 1

        await pipe.execute()

        logger.info("Stored %d IOCs in Redis cache", count)
        return count

    async def bulk_lookup_iocs(
        self, lookups: list[tuple[IOCType, str]]
    ) -> list[dict[str, Any] | None]:
        """Look up multiple IOCs efficiently using mget.

        Args:
            lookups: List of (ioc_type, value) tuples.

        Returns:
            List of IOC data dicts (or None for not found).
        """
        if not lookups:
            return []

        redis = await get_redis()
        keys = [self._make_key(ioc_type, value) for ioc_type, value in lookups]
        values = await redis.mget(keys)

        results = []
        for data in values:
            if data is None:
                results.append(None)
            else:
                results.append(json.loads(data))

        return results

    async def clear_all_iocs(self) -> int:
        """Clear all IOCs from cache.

        Returns:
            Number of IOCs deleted.
        """
        redis = await get_redis()
        # SCAN (non-blocking) instead of KEYS; include the reverse index.
        keys = await self._scan_keys(redis, f"{self.KEY_PREFIX}:*")
        keys += await self._scan_keys(redis, f"{self.ATTR_PREFIX}:*")

        if not keys:
            return 0

        # Delete in batches so a huge keyspace doesn't build one enormous command.
        ioc_deleted = 0
        for i in range(0, len(keys), 500):
            batch = keys[i:i + 500]
            deleted = await redis.delete(*batch)
            # Only count IOC value keys, not reverse-index keys.
            ioc_deleted += sum(1 for k in batch if not k.startswith(f"{self.ATTR_PREFIX}:"))
            _ = deleted
        logger.info("Cleared %d IOCs from Redis cache", ioc_deleted)
        return ioc_deleted

    async def get_ioc_count(self) -> int:
        """Get count of IOCs in cache.

        Uses non-blocking SCAN (not KEYS, which stalls the single-threaded Redis
        shared by the ingest hot path).

        Returns:
            Number of IOCs in cache.
        """
        redis = await get_redis()
        count = 0
        cursor = 0
        while True:
            cursor, batch = await redis.scan(cursor, match=f"{self.KEY_PREFIX}:*", count=500)
            count += len(batch)
            if cursor == 0:
                break
        return count

    async def evict_ioc(self, ioc_type: IOCType, value: str) -> bool:
        """Remove a single IOC from the cache.

        Used when marking an IOC as a false positive to immediately
        prevent future detections.

        Args:
            ioc_type: Type of IOC.
            value: IOC value to evict.

        Returns:
            True if IOC was found and deleted, False otherwise.
        """
        redis = await get_redis()
        key = self._make_key(ioc_type, value)
        deleted = await redis.delete(key)
        if deleted:
            logger.info("Evicted IOC from cache: %s:%s", ioc_type.value, value)
        return deleted > 0

    async def evict_by_attribute_uuid(self, attribute_uuid: str) -> bool:
        """Remove an IOC from cache by its MISP attribute UUID.

        O(1): looks up the attribute-UUID reverse index to find the IOC key
        directly, instead of scanning the whole IOC keyspace and GET-ing each key
        (which blocked the shared Redis on every false-positive click).

        Args:
            attribute_uuid: The MISP attribute UUID.

        Returns:
            True if IOC was found and deleted, False otherwise.
        """
        redis = await get_redis()
        attr_key = self._attr_key(attribute_uuid)
        ioc_key = await redis.get(attr_key)
        if not ioc_key:
            return False

        await redis.delete(ioc_key, attr_key)
        # Sanitize UUID for logging (remove newlines/control chars)
        safe_uuid = str(attribute_uuid).replace('\n', '').replace('\r', '')[:64]
        logger.info("Evicted IOC by attribute UUID: %s", safe_uuid)
        return True
