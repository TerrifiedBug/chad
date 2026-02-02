"""
Redis-based rate limiting for log ingestion.

Uses Redis sorted sets for accurate sliding window rate limiting
that works across multiple workers.
"""

import logging
import time

from fastapi import HTTPException

from app.core.redis import get_redis

logger = logging.getLogger(__name__)

# Key prefixes
REQUEST_KEY_PREFIX = "ratelimit:req:"
EVENT_KEY_PREFIX = "ratelimit:evt:"

# Window size in seconds
WINDOW_SECONDS = 60


async def check_rate_limit_redis(
    pattern_id: str,
    event_count: int,
    max_requests: int,
    max_events: int,
) -> None:
    """
    Check and enforce rate limits using Redis.

    Uses sorted sets with timestamps for accurate sliding window.
    Works correctly across multiple workers.

    Args:
        pattern_id: The index pattern ID
        event_count: Number of events in this request
        max_requests: Maximum requests per minute
        max_events: Maximum events per minute

    Raises:
        HTTPException: If rate limit is exceeded
    """
    redis = await get_redis()
    now = time.time()
    window_start = now - WINDOW_SECONDS

    request_key = f"{REQUEST_KEY_PREFIX}{pattern_id}"
    event_key = f"{EVENT_KEY_PREFIX}{pattern_id}"

    try:
        # Use pipeline for atomic operations
        pipe = redis.pipeline()

        # Remove old entries outside the window
        pipe.zremrangebyscore(request_key, 0, window_start)
        pipe.zremrangebyscore(event_key, 0, window_start)

        # Count current entries
        pipe.zcard(request_key)
        pipe.zrange(event_key, 0, -1, withscores=True)

        results = await pipe.execute()

        request_count = results[2]
        event_entries = results[3]

        # Calculate total events in window
        total_events = sum(
            int(member.split(":")[1]) if isinstance(member, str) and ":" in member else 0
            for member, score in event_entries
        )

        # Check request limit
        if request_count >= max_requests:
            logger.warning(
                f"Rate limit exceeded for {pattern_id}: {request_count}/{max_requests} requests"
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: too many requests ({max_requests}/minute)",
                headers={"Retry-After": "60"},
            )

        # Check event limit
        if total_events + event_count > max_events:
            logger.warning(
                f"Rate limit exceeded for {pattern_id}: {total_events + event_count}/{max_events} events"
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: too many events ({max_events}/minute)",
                headers={"Retry-After": "60"},
            )

        # Record this request (use unique member to avoid collisions)
        request_member = f"{now}:{id(now)}"
        event_member = f"{now}:{event_count}:{id(now)}"

        pipe2 = redis.pipeline()
        pipe2.zadd(request_key, {request_member: now})
        pipe2.zadd(event_key, {event_member: now})

        # Set expiry on keys (window + buffer)
        pipe2.expire(request_key, WINDOW_SECONDS + 10)
        pipe2.expire(event_key, WINDOW_SECONDS + 10)

        await pipe2.execute()

    except HTTPException:
        raise
    except Exception as e:
        # Log but don't fail if Redis is unavailable
        # Fall back to allowing the request (fail-open)
        logger.warning(f"Rate limit check failed, allowing request: {e}")


async def get_rate_limit_status(pattern_id: str) -> dict:
    """
    Get current rate limit status for an index pattern.

    Args:
        pattern_id: The index pattern ID

    Returns:
        Dict with current request and event counts
    """
    redis = await get_redis()
    now = time.time()
    window_start = now - WINDOW_SECONDS

    request_key = f"{REQUEST_KEY_PREFIX}{pattern_id}"
    event_key = f"{EVENT_KEY_PREFIX}{pattern_id}"

    try:
        pipe = redis.pipeline()
        pipe.zcount(request_key, window_start, now)
        pipe.zrange(event_key, 0, -1, withscores=True)
        results = await pipe.execute()

        request_count = results[0]
        event_entries = results[1]

        total_events = sum(
            int(member.split(":")[1]) if isinstance(member, str) and ":" in member else 0
            for member, score in event_entries
            if score >= window_start
        )

        return {
            "requests_in_window": request_count,
            "events_in_window": total_events,
            "window_seconds": WINDOW_SECONDS,
        }

    except Exception as e:
        logger.warning(f"Failed to get rate limit status: {e}")
        return {
            "requests_in_window": 0,
            "events_in_window": 0,
            "window_seconds": WINDOW_SECONDS,
            "error": str(e),
        }
