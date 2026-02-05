"""Redis cache layer for OpenSearch alert queries."""

import hashlib
import json
import logging

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

CACHE_KEY_PREFIX = "alerts:list:"


class AlertCache:
    """Cache alert query results in Redis with TTL-based expiry."""

    def __init__(self, redis: Redis, ttl: int = 30):
        self.redis = redis
        self.ttl = ttl

    def _build_key(
        self,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        owner_id: str | None = None,
        index_pattern: str = "chad-alerts-*",
        limit: int = 100,
        offset: int = 0,
        exclude_ioc: bool = False,
    ) -> str:
        """Build deterministic cache key from query params."""
        params = f"{status}:{severity}:{rule_id}:{owner_id}:{index_pattern}:{limit}:{offset}:{exclude_ioc}"
        key_hash = hashlib.md5(params.encode()).hexdigest()[:12]
        return f"{CACHE_KEY_PREFIX}{key_hash}"

    async def get_alerts(self, **kwargs) -> dict | None:
        """Get cached alert results. Returns None on miss."""
        key = self._build_key(**kwargs)
        try:
            data = await self.redis.get(key)
            if data is None:
                return None
            result = json.loads(data)
            logger.debug("Cache hit for %s", key)
            return result
        except Exception:
            logger.warning("Redis cache read error for %s", key, exc_info=True)
            return None

    async def set_alerts(self, data: dict, **kwargs) -> None:
        """Cache alert results with TTL."""
        key = self._build_key(**kwargs)
        try:
            payload = json.dumps(data, default=str)
            await self.redis.setex(key, self.ttl, payload)
            logger.debug("Cached %s (TTL=%ds)", key, self.ttl)
        except Exception:
            logger.warning("Redis cache write error for %s", key, exc_info=True)

    async def invalidate(self) -> None:
        """Invalidate all cached alert results."""
        try:
            keys = await self.redis.keys(f"{CACHE_KEY_PREFIX}*")
            for key in keys:
                await self.redis.delete(key)
            if keys:
                logger.info("Invalidated %d alert cache entries", len(keys))
        except Exception:
            logger.warning("Redis cache invalidation error", exc_info=True)
