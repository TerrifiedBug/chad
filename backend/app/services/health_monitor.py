"""
Health monitoring service that checks index health and triggers alerts.

Runs on a schedule to check all index patterns with health alerting enabled
and sends notifications when thresholds are exceeded.

Includes escalation-based suppression to prevent alert flooding:
- 1st alert: Fires immediately
- 2nd alert: 15 minute suppression
- 3rd alert: 1 hour suppression
- 4th+ alerts: 4 hour suppression
- When condition clears: Suppression resets
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_alert_suppression import HealthAlertSuppression
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


async def _get_suppression(
    db: AsyncSession, index_pattern_id: uuid.UUID, alert_type: str
) -> HealthAlertSuppression:
    """Get or create suppression record for an (index_pattern, alert_type) pair."""
    result = await db.execute(
        select(HealthAlertSuppression).where(
            HealthAlertSuppression.index_pattern_id == index_pattern_id,
            HealthAlertSuppression.alert_type == alert_type,
        )
    )
    suppression = result.scalar_one_or_none()

    if not suppression:
        suppression = HealthAlertSuppression(
            index_pattern_id=index_pattern_id,
            alert_type=alert_type,
            suppression_level=0,
        )
        db.add(suppression)

    return suppression


async def _clear_suppression(
    db: AsyncSession, index_pattern_id: uuid.UUID, alert_type: str
) -> None:
    """Clear suppression state when condition returns to healthy."""
    result = await db.execute(
        select(HealthAlertSuppression).where(
            HealthAlertSuppression.index_pattern_id == index_pattern_id,
            HealthAlertSuppression.alert_type == alert_type,
        )
    )
    suppression = result.scalar_one_or_none()

    if suppression and suppression.suppression_level > 0:
        suppression.clear()
        logger.debug(f"Cleared suppression for {alert_type} on index pattern {index_pattern_id}")


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

    Includes escalation-based suppression - when a condition returns to healthy,
    its suppression state is cleared.

    Returns list of health issues found (excludes suppressed alerts).
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
        # Track which conditions had issues for this pattern
        # If a condition is not in this set at the end, its suppression should be cleared
        conditions_with_issues: set[str] = set()

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
                conditions_with_issues.add("no_data")
                issue = await _handle_issue(
                    db,
                    pattern,
                    "warning",
                    "no_data",
                    f"No data received for {pattern.name}",
                    {"minutes_since_creation": int(time_since_creation.total_seconds() // 60)},
                )
                if issue:
                    issues.append(issue)
            # No metrics means we can't check other conditions
            continue

        # Check for stale data
        metric_age = datetime.now(UTC) - latest.timestamp.replace(tzinfo=UTC)
        age_minutes = int(metric_age.total_seconds() // 60)
        if age_minutes > no_data_minutes:
            conditions_with_issues.add("no_data")
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
            if issue:
                issues.append(issue)
        else:
            # Data is fresh - clear no_data suppression if it exists
            await _clear_suppression(db, pattern.id, "no_data")

        # Check error rate
        error_rate_healthy = True
        if latest.logs_received > 0:
            error_rate = (latest.logs_errored / latest.logs_received) * 100
            if error_rate > error_rate_percent:
                error_rate_healthy = False
                conditions_with_issues.add("error_rate")
                level = "critical" if error_rate > error_rate_percent * 2 else "warning"
                issue = await _handle_issue(
                    db,
                    pattern,
                    level,
                    "error_rate",
                    f"Error rate {error_rate:.1f}% exceeds threshold {error_rate_percent}%",
                    {"error_rate": error_rate, "threshold": error_rate_percent},
                )
                if issue:
                    issues.append(issue)

        if error_rate_healthy:
            await _clear_suppression(db, pattern.id, "error_rate")

        # Check latency
        latency_healthy = True
        if latest.avg_latency_ms and latest.avg_latency_ms > latency_ms:
            latency_healthy = False
            conditions_with_issues.add("latency")
            level = "critical" if latest.avg_latency_ms > latency_ms * 2 else "warning"
            issue = await _handle_issue(
                db,
                pattern,
                level,
                "latency",
                f"Latency {latest.avg_latency_ms}ms exceeds threshold {latency_ms}ms",
                {"latency_ms": latest.avg_latency_ms, "threshold_ms": latency_ms},
            )
            if issue:
                issues.append(issue)

        if latency_healthy:
            await _clear_suppression(db, pattern.id, "latency")

        # Check queue depth
        queue_healthy = True
        if latest.queue_depth:
            if latest.queue_depth > queue_critical:
                queue_healthy = False
                conditions_with_issues.add("queue_depth")
                issue = await _handle_issue(
                    db,
                    pattern,
                    "critical",
                    "queue_depth",
                    f"Queue depth {latest.queue_depth} exceeds critical threshold {queue_critical}",
                    {"queue_depth": latest.queue_depth, "threshold": queue_critical},
                )
                if issue:
                    issues.append(issue)
            elif latest.queue_depth > queue_warning:
                queue_healthy = False
                conditions_with_issues.add("queue_depth")
                issue = await _handle_issue(
                    db,
                    pattern,
                    "warning",
                    "queue_depth",
                    f"Queue depth {latest.queue_depth} exceeds warning threshold {queue_warning}",
                    {"queue_depth": latest.queue_depth, "threshold": queue_warning},
                )
                if issue:
                    issues.append(issue)

        if queue_healthy:
            await _clear_suppression(db, pattern.id, "queue_depth")

    return issues


async def _handle_issue(
    db: AsyncSession,
    pattern: IndexPattern,
    level: str,
    condition_type: str,
    message: str,
    details: dict,
) -> dict | None:
    """
    Handle a health issue with suppression logic.

    Returns the issue dict if alert was sent, None if suppressed.
    """
    # Get or create suppression record
    suppression = await _get_suppression(db, pattern.id, condition_type)

    # Check if we should suppress this alert
    if suppression.should_suppress():
        logger.debug(
            f"Suppressing {level} alert for {pattern.name} ({condition_type}) - "
            f"level {suppression.suppression_level}, "
            f"next alert in {_format_suppression_remaining(suppression)}"
        )
        return None

    # Not suppressed - record the alert and escalate
    suppression.record_alert()
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
        "suppression_level": suppression.suppression_level,
    }


def _format_suppression_remaining(suppression: HealthAlertSuppression) -> str:
    """Format the time remaining until next alert can fire."""
    if suppression.last_alert_at is None:
        return "0s"

    interval = suppression.SUPPRESSION_INTERVALS[min(suppression.suppression_level, 3)]
    elapsed = (datetime.now(UTC) - suppression.last_alert_at).total_seconds()
    remaining = max(0, interval - elapsed)

    if remaining >= 3600:
        return f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m"
    elif remaining >= 60:
        return f"{int(remaining // 60)}m"
    else:
        return f"{int(remaining)}s"
