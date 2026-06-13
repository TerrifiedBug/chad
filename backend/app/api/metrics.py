"""Prometheus metrics endpoint."""

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from app.core.config import settings
from app.core.redis import get_redis_queue

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(authorization: Annotated[str | None, Header()] = None):
    """
    Return Prometheus-format metrics.

    Exposes:
    - chad_queue_depth{index="<index>"}: Queue depth per index
    - chad_queue_depth_total: Total queue depth across all indexes
    - chad_dead_letter_count: Dead letter queue size
    - chad_redis_connected: Redis connection status (1=connected, 0=disconnected)

    Protected by an optional bearer token: if settings.METRICS_TOKEN is set, the
    request must send "Authorization: Bearer <token>". Otherwise the endpoint is
    open (Prometheus default). Without a token the response would leak per-index
    queue inventory to any unauthenticated caller.
    """
    expected_token = settings.METRICS_TOKEN
    if expected_token:
        provided = (
            authorization[7:]
            if authorization and authorization.startswith("Bearer ")
            else None
        )
        if not provided or not secrets.compare_digest(provided, expected_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing metrics token",
            )

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
        redis = await get_redis_queue()

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

    # Queue/redis gauges (above) followed by the registered pipeline metrics
    # (ingest throughput, alerts, batch failures, processing latency).
    queue_section = "\n".join(lines) + "\n"
    try:
        from prometheus_client import generate_latest

        pipeline_section = generate_latest().decode("utf-8")
    except Exception as e:
        logger.warning("Failed to render pipeline metrics: %s", e)
        pipeline_section = ""

    return queue_section + pipeline_section
