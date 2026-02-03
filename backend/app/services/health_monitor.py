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

from dateutil.parser import parse as parse_timestamp
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_alert_suppression import HealthAlertSuppression
from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleStatus
from app.services.notification import send_health_notification
from app.services.opensearch import get_client_from_settings
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
        logger.debug("Cleared suppression for %s on index pattern %s", alert_type, index_pattern_id)


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


def _get_nested_field(doc: dict, field_path: str):
    """
    Get a value from a nested dictionary using dot notation.

    Args:
        doc: The document dictionary
        field_path: Dot-separated field path (e.g., "event.created")

    Returns:
        The value at the path, or None if not found
    """
    parts = field_path.split(".")
    current = doc
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


async def check_index_data_freshness(
    os_client,
    index_pattern,
    threshold_minutes: int = 15,
) -> tuple[bool, dict]:
    """
    Check if data in an OpenSearch index is fresh or stale.

    This function queries OpenSearch for the most recent event timestamp in an index
    to determine if data is being received. This is useful for pull mode health checks
    where CHAD polling works fine but the upstream log shipper may have stopped
    sending data to OpenSearch.

    Args:
        os_client: OpenSearch client (async)
        index_pattern: IndexPattern object with 'pattern' and 'timestamp_field' attributes
        threshold_minutes: Maximum age of data in minutes before considered stale (default 15)

    Returns:
        Tuple of (is_fresh: bool, details: dict)
        - is_fresh: True if data is within threshold, False otherwise
        - details: Dict with status and additional information:
            - status: "fresh", "stale", "no_data", "no_timestamp", or "error"
            - Additional fields depend on status
    """
    index = index_pattern.pattern
    timestamp_field = getattr(index_pattern, "timestamp_field", "@timestamp") or "@timestamp"

    try:
        # Query for the single most recent document sorted by timestamp
        # Note: OpenSearch client is synchronous
        response = os_client.search(
            index=index,
            body={
                "size": 1,
                "sort": [{timestamp_field: {"order": "desc"}}],
                "_source": [timestamp_field],
            },
        )

        hits = response.get("hits", {}).get("hits", [])

        # Handle no documents found
        if not hits:
            return (False, {
                "status": "no_data",
                "message": "No events found in index",
                "index": index,
            })

        # Get the latest document
        latest_doc = hits[0].get("_source", {})

        # Extract timestamp using the configured field (handle nested fields)
        timestamp_value = _get_nested_field(latest_doc, timestamp_field)

        # Handle missing timestamp field
        if timestamp_value is None:
            return (False, {
                "status": "no_timestamp",
                "message": f"Latest event missing {timestamp_field} field",
                "index": index,
            })

        # Parse the timestamp and calculate age
        # Handle numeric timestamps (Unix epoch seconds or milliseconds)
        if isinstance(timestamp_value, (int, float)):
            # Assume milliseconds if value > 10 billion (after year 2001 in ms)
            if timestamp_value > 1e10:
                timestamp_value = timestamp_value / 1000
            last_event_time = datetime.fromtimestamp(timestamp_value, tz=UTC)
        else:
            last_event_time = parse_timestamp(timestamp_value)
            # Ensure timezone-aware comparison
            if last_event_time.tzinfo is None:
                last_event_time = last_event_time.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        age = now - last_event_time
        age_minutes = int(age.total_seconds() / 60)

        # Determine if data is fresh or stale
        if age_minutes <= threshold_minutes:
            return (True, {
                "status": "fresh",
                "last_event_at": last_event_time.isoformat(),
                "age_minutes": age_minutes,
                "threshold_minutes": threshold_minutes,
                "index": index,
            })
        else:
            return (False, {
                "status": "stale",
                "last_event_at": last_event_time.isoformat(),
                "age_minutes": age_minutes,
                "threshold_minutes": threshold_minutes,
                "index": index,
            })

    except Exception as e:
        logger.error("Failed to check data freshness for %s: %s", index, e)
        return (False, {
            "status": "error",
            "message": f"Failed to query index: {e}",
            "index": index,
        })


async def check_index_health(db: AsyncSession, os_client=None) -> list[dict]:
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

    # Get OpenSearch client for data freshness checks (only for pull mode)
    pull_patterns = [p for p in patterns if p.mode == "pull"]
    if pull_patterns and os_client is None:
        try:
            os_client = await get_client_from_settings(db)
        except Exception as e:
            logger.warning("Could not get OpenSearch client for data freshness checks: %s", e)

    for pattern in patterns:
        # For pull-mode patterns, skip health checks if no deployed rules exist
        # This prevents false "no data" alerts when all rules are disabled
        if pattern.mode == "pull":
            deployed_rules_count = await db.scalar(
                select(func.count(Rule.id))
                .where(Rule.index_pattern_id == pattern.id)
                .where(Rule.status == RuleStatus.DEPLOYED)
            )
            if deployed_rules_count == 0:
                logger.debug(
                    "Skipping health check for %s: no deployed rules (pull mode)",
                    pattern.name,
                )
                continue

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
        if latest.avg_detection_latency_ms and latest.avg_detection_latency_ms > latency_ms:
            latency_healthy = False
            conditions_with_issues.add("latency")
            level = "critical" if latest.avg_detection_latency_ms > latency_ms * 2 else "warning"
            issue = await _handle_issue(
                db,
                pattern,
                level,
                "latency",
                f"Latency {latest.avg_detection_latency_ms / 1000:.1f}s exceeds threshold {latency_ms / 1000:.1f}s",
                {"latency_ms": latest.avg_detection_latency_ms, "threshold_ms": latency_ms},
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

        # For pull mode, also check actual index data freshness
        if pattern.mode == "pull" and os_client:
            is_fresh, freshness_details = await check_index_data_freshness(
                os_client,
                pattern,
                threshold_minutes=no_data_minutes  # Reuse no_data threshold
            )

            if not is_fresh and freshness_details["status"] in ("stale", "no_data"):
                conditions_with_issues.add("stale_data")
                issue = await _handle_issue(
                    db,
                    pattern,
                    "warning",
                    "stale_data",
                    f"Index data is stale - last event was {freshness_details.get('age_minutes', '?')} minutes ago"
                    if freshness_details["status"] == "stale"
                    else "No events found in index",
                    freshness_details,
                )
                if issue:
                    issues.append(issue)
            elif is_fresh:
                # Data is fresh - clear stale_data suppression
                await _clear_suppression(db, pattern.id, "stale_data")

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
            "Suppressing %s alert for %s (%s) - level %d, next alert in %s",
            level,
            pattern.name,
            condition_type,
            suppression.suppression_level,
            _format_suppression_remaining(suppression),
        )
        return None

    # Not suppressed - record the alert and escalate
    suppression.record_alert()
    logger.warning("Health %s for %s: %s", level, pattern.name, message)

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
