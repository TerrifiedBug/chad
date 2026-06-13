# backend/app/core/redis.py
"""Redis clients for distributed locking, caching, and durable queue management.

Two logical clients:
- ``get_redis()`` — cache / locks / rate-limit / pub-sub. May run an eviction
  policy (e.g. allkeys-lru); losing a cache entry is harmless.
- ``get_redis_queue()`` — the durable Redis Streams log queue. Must run on a
  ``noeviction`` instance so queued-but-unprocessed logs are never silently
  evicted (which would drop undetected events). Defaults to the same URL as the
  cache client when ``REDIS_QUEUE_URL`` is unset, so single-Redis dev/test setups
  keep working unchanged.
"""

import os

import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
# Durable queue Redis; falls back to the cache Redis if not separately configured.
REDIS_QUEUE_URL = os.getenv("REDIS_QUEUE_URL", REDIS_URL)

redis_client: redis.Redis | None = None
redis_queue_client: redis.Redis | None = None


def _new_client(url: str) -> redis.Redis:
    # Connection-level resilience. NOTE: socket_timeout is intentionally left
    # unset — the worker issues blocking reads (XREADGROUP BLOCK 5000ms) and a
    # short read timeout would abort them. These options only affect connection
    # setup/health, a bounded pool, and keepalive, so they do not interfere
    # with blocking commands.
    return redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_keepalive=True,
        health_check_interval=30,
        retry_on_timeout=True,
        max_connections=50,
    )


async def get_redis() -> redis.Redis:
    """
    Get the cache/locks Redis client, creating if needed.

    Returns a singleton Redis client instance. Thread-safe for async usage.
    """
    global redis_client
    if redis_client is None:
        redis_client = _new_client(REDIS_URL)
    return redis_client


async def get_redis_queue() -> redis.Redis:
    """
    Get the durable-queue Redis client (separate pool / possibly separate server).

    Used for the Redis Streams log queue, which must not be subject to cache
    eviction. Returns the same singleton as ``get_redis()`` when REDIS_QUEUE_URL
    is not separately configured.
    """
    global redis_queue_client
    if REDIS_QUEUE_URL == REDIS_URL:
        return await get_redis()
    if redis_queue_client is None:
        redis_queue_client = _new_client(REDIS_QUEUE_URL)
    return redis_queue_client


async def close_redis() -> None:
    """
    Close Redis connections.

    Should be called during application shutdown.
    """
    global redis_client, redis_queue_client
    if redis_client:
        await redis_client.close()
        redis_client = None
    if redis_queue_client:
        await redis_queue_client.close()
        redis_queue_client = None
