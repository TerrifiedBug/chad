"""Prometheus metrics endpoint."""

import logging

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.core.redis import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """
    Return Prometheus-format metrics.

    Exposes:
    - chad_queue_depth{index="<index>"}: Queue depth per index
    - chad_queue_depth_total: Total queue depth across all indexes
    - chad_dead_letter_count: Dead letter queue size
    - chad_redis_connected: Redis connection status (1=connected, 0=disconnected)
    """
    lines = []

    # Help and type declarations
    lines.append("# HELP chad_queue_depth Number of messages in queue per index")
    lines.append("# TYPE chad_queue_depth gauge")
    lines.append("# HELP chad_queue_depth_total Total messages across all queues")
    lines.append("# TYPE chad_queue_depth_total gauge")
    lines.append("# HELP chad_dead_letter_count Messages in dead letter queue")
    lines.append("# TYPE chad_dead_letter_count gauge")
    lines.append("# HELP chad_redis_connected Redis connection status")
    lines.append("# TYPE chad_redis_connected gauge")

    try:
        redis = await get_redis()

        # Test connection
        await redis.ping()
        lines.append("chad_redis_connected 1")

        # Queue depth per index
        total_depth = 0
        cursor = 0

        while True:
            cursor, keys = await redis.scan(cursor, match="chad:logs:*", count=100)
            for key in keys:
                if "dead-letter" not in key:
                    depth = await redis.xlen(key)
                    total_depth += depth
                    index = key.replace("chad:logs:", "")
                    lines.append(f'chad_queue_depth{{index="{index}"}} {depth}')
            if cursor == 0:
                break

        lines.append(f"chad_queue_depth_total {total_depth}")

        # Dead letter count
        dl_count = await redis.xlen("chad:logs:dead-letter")
        lines.append(f"chad_dead_letter_count {dl_count}")

    except Exception as e:
        logger.warning("Redis unavailable for metrics: %s", e)
        lines.append("chad_redis_connected 0")
        lines.append("chad_queue_depth_total 0")
        lines.append("chad_dead_letter_count 0")

    return "\n".join(lines) + "\n"
