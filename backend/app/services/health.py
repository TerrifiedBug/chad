"""Health monitoring service."""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern


# Thresholds (could be moved to settings)
QUEUE_WARNING_THRESHOLD = 10000
QUEUE_CRITICAL_THRESHOLD = 100000
LATENCY_WARNING_MS = 500
LATENCY_CRITICAL_MS = 2000
ERROR_RATE_WARNING = 0.01
ERROR_RATE_CRITICAL = 0.05


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
    index_pattern_id: uuid.UUID,
    hours: int = 24,
) -> dict:
    """Get health summary for an index pattern."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Get latest metrics
    result = await db.execute(
        select(IndexHealthMetrics)
        .where(IndexHealthMetrics.index_pattern_id == index_pattern_id)
        .order_by(IndexHealthMetrics.timestamp.desc())
        .limit(1)
    )
    latest = result.scalar_one_or_none()

    if not latest:
        return {
            "status": HealthStatus.HEALTHY,
            "message": "No data",
            "issues": [],
            "latest": {
                "queue_depth": 0,
                "avg_latency_ms": 0,
                "logs_per_minute": 0,
                "alerts_per_hour": 0,
            },
            "totals_24h": {
                "logs_received": 0,
                "logs_errored": 0,
                "alerts_generated": 0,
            },
        }

    # Calculate status
    status = HealthStatus.HEALTHY
    issues = []

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
            "alerts_per_hour": latest.alerts_generated * 60,  # Extrapolate from per-minute
        },
        "totals_24h": {
            "logs_received": logs_received,
            "logs_errored": logs_errored,
            "alerts_generated": alerts_generated,
        },
    }


async def get_all_indices_health(db: AsyncSession) -> list[dict]:
    """Get health summary for all index patterns."""
    result = await db.execute(select(IndexPattern))
    patterns = result.scalars().all()

    health_data = []
    for pattern in patterns:
        health = await get_index_health(db, pattern.id)
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
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

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
