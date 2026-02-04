"""
Redis-based rate limiting for API key authentication.

Uses Redis sorted sets for accurate sliding window rate limiting
that works across multiple workers.
"""

import logging
import time

from fastapi import HTTPException

from app.core.config import settings
from app.core.redis import get_redis

logger = logging.getLogger(__name__)

# Key prefix
API_KEY_PREFIX = "ratelimit:api:"

# Window size in seconds
WINDOW_SECONDS = 60


async def check_api_key_rate_limit(
    api_key_id: str,
    max_requests: int | None = None,
) -> None:
    """
    Check and enforce rate limits for API key requests using Redis.

    Uses sorted sets with timestamps for accurate sliding window.
    Works correctly across multiple workers.

    Args:
        api_key_id: The API key ID (UUID)
        max_requests: Maximum requests per minute for this API key

    Raises:
        HTTPException: If rate limit is exceeded (429)
    """
    if max_requests is None:
        max_requests = settings.API_KEY_RATE_LIMIT

    redis = await get_redis()
    now = time.time()
    window_start = now - WINDOW_SECONDS

    rate_limit_key = f"{API_KEY_PREFIX}{api_key_id}"

    try:
        # Use pipeline for atomic operations
        pipe = redis.pipeline()

        # Remove old entries outside the window
        pipe.zremrangebyscore(rate_limit_key, 0, window_start)

        # Count current entries
        pipe.zcard(rate_limit_key)

        results = await pipe.execute()
        request_count = results[1]

        # Check request limit
        if request_count >= max_requests:
            logger.warning(
                "API key rate limit exceeded: %s - %d/%d requests",
                api_key_id,
                request_count,
                max_requests,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {max_requests} requests per minute allowed",
                headers={"Retry-After": "60"},
            )

        # Record this request (use unique member to avoid collisions)
        request_member = f"{now}:{id(now)}"

        pipe2 = redis.pipeline()
        pipe2.zadd(rate_limit_key, {request_member: now})

        # Set expiry on key (window + buffer)
        pipe2.expire(rate_limit_key, WINDOW_SECONDS + 10)

        await pipe2.execute()

    except HTTPException:
        raise
    except Exception as e:
        # Log but don't fail if Redis is unavailable
        # Fall back to allowing the request (fail-open)
        logger.warning("API key rate limit check failed, allowing request: %s", e)


async def get_api_key_rate_limit_status(api_key_id: str) -> dict:
    """
    Get current rate limit status for an API key.

    Args:
        api_key_id: The API key ID (UUID)

    Returns:
        Dict with current request count and window info
    """
    redis = await get_redis()
    now = time.time()
    window_start = now - WINDOW_SECONDS

    rate_limit_key = f"{API_KEY_PREFIX}{api_key_id}"

    try:
        request_count = await redis.zcount(rate_limit_key, window_start, now)

        return {
            "requests_in_window": request_count,
            "window_seconds": WINDOW_SECONDS,
        }

    except Exception as e:
        logger.warning("Failed to get API key rate limit status: %s", e)
        return {
            "requests_in_window": 0,
            "window_seconds": WINDOW_SECONDS,
            "error": str(e),
        }
