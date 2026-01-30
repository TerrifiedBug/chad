# backend/app/core/redis.py
"""Redis client for distributed locking and queue management."""

import os

import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

redis_client: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    """
    Get Redis client, creating if needed.

    Returns a singleton Redis client instance. Thread-safe for async usage.
    """
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    return redis_client


async def close_redis() -> None:
    """
    Close Redis connection.

    Should be called during application shutdown.
    """
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None
