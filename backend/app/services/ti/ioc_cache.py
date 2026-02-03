"""Redis IOC cache for fast Push Mode lookups."""

import json
import logging
from datetime import datetime, UTC
from typing import Any

from app.core.redis import get_redis
from app.services.ti.ioc_types import IOCType, IOCRecord

logger = logging.getLogger(__name__)


class IOCCache:
    """Redis-backed cache for IOC lookups."""

    KEY_PREFIX = "chad:ioc"

    def _make_key(self, ioc_type: IOCType, value: str) -> str:
        """Generate Redis key for an IOC."""
        return f"{self.KEY_PREFIX}:{ioc_type.value}:{value}"

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
        keys = await redis.keys(f"{self.KEY_PREFIX}:*")

        if not keys:
            return 0

        count = await redis.delete(*keys)
        logger.info("Cleared %d IOCs from Redis cache", count)
        return count

    async def get_ioc_count(self) -> int:
        """Get count of IOCs in cache.

        Returns:
            Number of IOCs in cache.
        """
        redis = await get_redis()
        keys = await redis.keys(f"{self.KEY_PREFIX}:*")
        return len(keys)
