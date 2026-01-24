"""
Health monitoring service that checks index health and triggers alerts.

Runs on a schedule to check all index patterns with health alerting enabled
and sends notifications when thresholds are exceeded.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern
from app.services.notification import send_health_notification
from app.services.settings import get_setting

logger = logging.getLogger(__name__)

# Default thresholds (used when index pattern doesn't override and no global setting)
DEFAULT_NO_DATA_MINUTES = 15
DEFAULT_ERROR_RATE_PERCENT = 5.0
DEFAULT_LATENCY_MS = 1000
DEFAULT_QUEUE_WARNING = 10000
DEFAULT_QUEUE_CRITICAL = 100000


async def _get_thresholds(db: AsyncSession) -> dict:
    """Get all threshold values from settings with fallbacks to defaults."""
    setting = await get_setting(db, "health_thresholds")
    thresholds = setting or {}
    return {
        "no_data_minutes": thresholds.get("no_data_minutes", DEFAULT_NO_DATA_MINUTES),
        "error_rate_percent": thresholds.get("error_rate_percent", DEFAULT_ERROR_RATE_PERCENT),
        "latency_ms": thresholds.get("latency_ms", DEFAULT_LATENCY_MS),
        "queue_warning": thresholds.get("queue_warning", DEFAULT_QUEUE_WARNING),
        "queue_critical": thresholds.get("queue_critical", DEFAULT_QUEUE_CRITICAL),
    }


async def check_index_health(db: AsyncSession) -> list[dict]:
    """
    Check health of all index patterns and send notifications for issues.

    Returns list of health issues found.
    """
    issues = []

    # Get all global thresholds from settings in a single query
    thresholds = await _get_thresholds(db)
    global_no_data = thresholds["no_data_minutes"]
    global_error_rate = thresholds["error_rate_percent"]
    global_latency = thresholds["latency_ms"]
    queue_warning = thresholds["queue_warning"]
    queue_critical = thresholds["queue_critical"]

    # Get all index patterns with alerting enabled
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.health_alerting_enabled == True)  # noqa: E712
    )
    patterns = result.scalars().all()

    for pattern in patterns:
        # Get thresholds (per-index or global)
        no_data_minutes = pattern.health_no_data_minutes or global_no_data
        error_rate_percent = pattern.health_error_rate_percent or global_error_rate
        latency_ms = pattern.health_latency_ms or global_latency

        # Get latest health metrics for this index
        metrics_result = await db.execute(
            select(IndexHealthMetrics)
            .where(IndexHealthMetrics.index_pattern_id == pattern.id)
            .order_by(IndexHealthMetrics.timestamp.desc())
            .limit(1)
        )
        latest = metrics_result.scalar_one_or_none()

        if not latest:
            # No metrics yet, check if pattern was created more than threshold ago
            time_since_creation = datetime.now(UTC) - pattern.created_at.replace(tzinfo=UTC)
            if time_since_creation > timedelta(minutes=no_data_minutes):
                issue = await _handle_issue(
                    db,
                    pattern,
                    "warning",
                    "no_data",
                    f"No data received for {pattern.name}",
                    {"minutes_since_creation": int(time_since_creation.total_seconds() // 60)},
                )
                issues.append(issue)
            continue

        # Check for stale data
        metric_age = datetime.now(UTC) - latest.timestamp.replace(tzinfo=UTC)
        age_minutes = int(metric_age.total_seconds() // 60)
        if age_minutes > no_data_minutes:
            issue = await _handle_issue(
                db,
                pattern,
                "warning",
                "no_data",
                f"No data received for {age_minutes} minutes",
                {
                    "last_data_at": latest.timestamp.isoformat(),
                    "threshold_minutes": no_data_minutes,
                },
            )
            issues.append(issue)

        # Check error rate
        if latest.logs_received > 0:
            error_rate = (latest.logs_errored / latest.logs_received) * 100
            if error_rate > error_rate_percent:
                level = "critical" if error_rate > error_rate_percent * 2 else "warning"
                issue = await _handle_issue(
                    db,
                    pattern,
                    level,
                    "error_rate",
                    f"Error rate {error_rate:.1f}% exceeds threshold {error_rate_percent}%",
                    {"error_rate": error_rate, "threshold": error_rate_percent},
                )
                issues.append(issue)

        # Check latency
        if latest.avg_latency_ms and latest.avg_latency_ms > latency_ms:
            level = "critical" if latest.avg_latency_ms > latency_ms * 2 else "warning"
            issue = await _handle_issue(
                db,
                pattern,
                level,
                "latency",
                f"Latency {latest.avg_latency_ms}ms exceeds threshold {latency_ms}ms",
                {"latency_ms": latest.avg_latency_ms, "threshold_ms": latency_ms},
            )
            issues.append(issue)

        # Check queue depth
        if latest.queue_depth:
            if latest.queue_depth > queue_critical:
                issue = await _handle_issue(
                    db,
                    pattern,
                    "critical",
                    "queue_depth",
                    f"Queue depth {latest.queue_depth} exceeds critical threshold {queue_critical}",
                    {"queue_depth": latest.queue_depth, "threshold": queue_critical},
                )
                issues.append(issue)
            elif latest.queue_depth > queue_warning:
                issue = await _handle_issue(
                    db,
                    pattern,
                    "warning",
                    "queue_depth",
                    f"Queue depth {latest.queue_depth} exceeds warning threshold {queue_warning}",
                    {"queue_depth": latest.queue_depth, "threshold": queue_warning},
                )
                issues.append(issue)

    return issues


async def _handle_issue(
    db: AsyncSession,
    pattern: IndexPattern,
    level: str,
    condition_type: str,
    message: str,
    details: dict,
) -> dict:
    """Handle a health issue - log and send notification."""
    logger.warning(f"Health {level} for {pattern.name}: {message}")

    # Send notification
    await send_health_notification(
        db,
        level=level,
        index_pattern=pattern.name,
        condition=message,
        details=details,
    )

    return {
        "index_pattern": pattern.name,
        "level": level,
        "condition_type": condition_type,
        "message": message,
        "details": details,
    }
