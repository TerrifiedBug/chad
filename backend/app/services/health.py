"""Health monitoring service."""

import uuid
from datetime import UTC, datetime, timedelta

from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern


def get_alert_count(
    os_client: OpenSearch,
    alerts_index_pattern: str,
    since: datetime,
) -> int:
    """
    Get actual alert count from OpenSearch for a time period.

    Args:
        os_client: OpenSearch client
        alerts_index_pattern: Alert index pattern (e.g., "chad-alerts-*")
        since: Start of time range

    Returns:
        Count of alerts in the time period
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        # Strip timezone info to match Dashboard's datetime format
        # OpenSearch handles naive datetimes more consistently
        since_naive = since.replace(tzinfo=None)

        query = {
            "query": {
                "range": {
                    "created_at": {
                        "gte": since_naive.isoformat()
                    }
                }
            }
        }

        logger.info(f"Counting alerts in {alerts_index_pattern} since {since_naive.isoformat()}")
        logger.info(f"Query: {query}")

        result = os_client.count(
            index=alerts_index_pattern,
            body=query
        )

        count = result.get("count", 0)
        logger.info(f"Alert count result for {alerts_index_pattern}: {count}")
        return count
    except Exception as e:
        logger.error(f"Failed to count alerts in {alerts_index_pattern}: {e}")
        return 0

# Thresholds (could be moved to settings)
QUEUE_WARNING_THRESHOLD = 10000
QUEUE_CRITICAL_THRESHOLD = 100000
LATENCY_WARNING_MS = 500
LATENCY_CRITICAL_MS = 2000
ERROR_RATE_WARNING = 0.01
ERROR_RATE_CRITICAL = 0.05

# No data thresholds (in minutes)
DEFAULT_NO_DATA_WARNING_MINUTES = 15
DEFAULT_NO_DATA_CRITICAL_MINUTES = 30


class HealthStatus:
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"


def _max_status(current: str, new: str) -> str:
    """Return the more severe status."""
    order = {HealthStatus.HEALTHY: 0, HealthStatus.WARNING: 1, HealthStatus.CRITICAL: 2}
    return new if order.get(new, 0) > order.get(current, 0) else current


async def get_index_health(
    db: AsyncSession,
    os_client: OpenSearch,
    index_pattern_id: uuid.UUID,
    hours: int = 24,
) -> dict:
    """Get health summary for an index pattern."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    # Convert to naive datetime for OpenSearch query consistency
    since_naive = since.replace(tzinfo=None)

    # Get index pattern settings for thresholds
    pattern_result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == index_pattern_id)
    )
    index_pattern = pattern_result.scalar_one_or_none()

    # Get custom thresholds or use defaults
    no_data_warning_minutes = (
        index_pattern.health_no_data_minutes
        if index_pattern and index_pattern.health_no_data_minutes
        else DEFAULT_NO_DATA_WARNING_MINUTES
    )
    no_data_critical_minutes = no_data_warning_minutes * 2  # Critical is 2x the warning threshold

    # Query actual alert counts from OpenSearch
    # Use wildcard to catch all alerts indices (pattern-specific and date-based)
    alerts_index = "chad-alerts-*"

    # Per-hour count (last hour)
    one_hour_ago = datetime.now(UTC) - timedelta(hours=1)
    one_hour_ago_naive = one_hour_ago.replace(tzinfo=None)
    alerts_per_hour = get_alert_count(os_client, alerts_index, one_hour_ago_naive)

    # 24-hour total
    alerts_24h = get_alert_count(os_client, alerts_index, since_naive)

    # Get latest metrics
    result = await db.execute(
        select(IndexHealthMetrics)
        .where(IndexHealthMetrics.index_pattern_id == index_pattern_id)
        .order_by(IndexHealthMetrics.timestamp.desc())
        .limit(1)
    )
    latest = result.scalar_one_or_none()

    if not latest:
        # No metrics at all - this is a warning state (index may not be configured or receiving logs)
        # But we still have OpenSearch query results for alert counts
        return {
            "status": HealthStatus.WARNING,
            "message": "No data received",
            "issues": ["No data received - index may not be configured or receiving logs"],
            "latest": {
                "queue_depth": 0,
                "avg_latency_ms": 0,
                "logs_per_minute": 0,
                "alerts_per_hour": alerts_per_hour,  # From OpenSearch query
            },
            "totals_24h": {
                "logs_received": 0,
                "logs_errored": 0,
                "alerts_generated": alerts_24h,  # From OpenSearch query
            },
        }

    # Calculate status
    status = HealthStatus.HEALTHY
    issues = []

    # Check time since last data
    now = datetime.now(UTC)
    time_since_last = now - latest.timestamp.replace(tzinfo=UTC)
    minutes_since_last = time_since_last.total_seconds() / 60

    if minutes_since_last >= no_data_critical_minutes:
        status = HealthStatus.CRITICAL
        issues.append(f"No data received for {int(minutes_since_last)} minutes")
    elif minutes_since_last >= no_data_warning_minutes:
        status = _max_status(status, HealthStatus.WARNING)
        issues.append(f"No data received for {int(minutes_since_last)} minutes")

    if latest.queue_depth >= QUEUE_CRITICAL_THRESHOLD:
        status = HealthStatus.CRITICAL
        issues.append(f"Queue depth critical: {latest.queue_depth}")
    elif latest.queue_depth >= QUEUE_WARNING_THRESHOLD:
        status = _max_status(status, HealthStatus.WARNING)
        issues.append(f"Queue depth elevated: {latest.queue_depth}")

    if latest.avg_latency_ms >= LATENCY_CRITICAL_MS:
        status = HealthStatus.CRITICAL
        issues.append(f"Latency critical: {latest.avg_latency_ms}ms")
    elif latest.avg_latency_ms >= LATENCY_WARNING_MS:
        status = _max_status(status, HealthStatus.WARNING)
        issues.append(f"Latency elevated: {latest.avg_latency_ms}ms")

    # Get aggregated metrics for time range
    agg_result = await db.execute(
        select(
            func.sum(IndexHealthMetrics.logs_received),
            func.sum(IndexHealthMetrics.logs_errored),
            func.sum(IndexHealthMetrics.alerts_generated),
        )
        .where(IndexHealthMetrics.index_pattern_id == index_pattern_id)
        .where(IndexHealthMetrics.timestamp >= since)
    )
    totals = agg_result.one()

    logs_received = totals[0] or 0
    logs_errored = totals[1] or 0
    alerts_generated = totals[2] or 0

    error_rate = logs_errored / logs_received if logs_received > 0 else 0
    if error_rate >= ERROR_RATE_CRITICAL:
        status = HealthStatus.CRITICAL
        issues.append(f"Error rate critical: {error_rate:.1%}")
    elif error_rate >= ERROR_RATE_WARNING:
        status = _max_status(status, HealthStatus.WARNING)
        issues.append(f"Error rate elevated: {error_rate:.1%}")

    return {
        "status": status,
        "issues": issues,
        "latest": {
            "queue_depth": latest.queue_depth,
            "avg_latency_ms": latest.avg_latency_ms,
            "logs_per_minute": latest.logs_received,
            "alerts_per_hour": alerts_per_hour,  # From OpenSearch
        },
        "totals_24h": {
            "logs_received": logs_received,
            "logs_errored": logs_errored,
            "alerts_generated": alerts_generated,  # From database metrics
        },
    }


async def get_all_indices_health(
    db: AsyncSession,
    os_client: OpenSearch,
) -> list[dict]:
    """Get health summary for all index patterns."""
    result = await db.execute(select(IndexPattern))
    patterns = result.scalars().all()

    health_data = []
    for pattern in patterns:
        health = await get_index_health(db, os_client, pattern.id)
        health_data.append(
            {
                "index_pattern_id": str(pattern.id),
                "index_pattern_name": pattern.name,
                "pattern": pattern.pattern,
                **health,
            }
        )

    return health_data


async def get_health_history(
    db: AsyncSession,
    index_pattern_id: uuid.UUID,
    hours: int = 24,
) -> list[dict]:
    """Get historical metrics for sparkline charts."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    result = await db.execute(
        select(IndexHealthMetrics)
        .where(IndexHealthMetrics.index_pattern_id == index_pattern_id)
        .where(IndexHealthMetrics.timestamp >= since)
        .order_by(IndexHealthMetrics.timestamp)
    )
    metrics = result.scalars().all()

    return [
        {
            "timestamp": m.timestamp.isoformat(),
            "logs_received": m.logs_received,
            "queue_depth": m.queue_depth,
            "avg_latency_ms": m.avg_latency_ms,
            "alerts_generated": m.alerts_generated,
        }
        for m in metrics
    ]
