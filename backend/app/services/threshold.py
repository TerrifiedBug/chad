"""
Threshold alerting service.

Handles counting matches and determining when threshold-based alerts should fire.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule import Rule
from app.models.threshold_state import ThresholdMatch


def extract_field(doc: dict, field_path: str) -> str | None:
    """Extract nested field value from document using dot notation."""
    parts = field_path.split(".")
    value = doc
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return str(value) if value is not None else None


async def check_threshold(
    db: AsyncSession,
    rule: Rule,
    log_document: dict,
    log_id: str,
) -> bool:
    """
    Check if threshold is met for a rule match.

    When a rule with threshold alerting matches a log, we record the match
    and check if the count within the time window exceeds the threshold.

    Returns True if alert should be created, False otherwise.

    For rules without threshold enabled, always returns True.
    """
    if not rule.threshold_enabled:
        return True  # No threshold, always alert

    if not rule.threshold_count or not rule.threshold_window_minutes:
        return True  # Threshold config incomplete, fall back to immediate alert

    # Extract group value if configured
    group_value = None
    if rule.threshold_group_by:
        group_value = extract_field(log_document, rule.threshold_group_by)

    # Store this match
    match = ThresholdMatch(
        rule_id=rule.id,
        group_value=group_value,
        log_id=log_id,
    )
    db.add(match)
    await db.flush()

    # Count matches in window
    window_start = datetime.now(timezone.utc) - timedelta(minutes=rule.threshold_window_minutes)

    query = select(func.count(ThresholdMatch.id)).where(
        ThresholdMatch.rule_id == rule.id,
        ThresholdMatch.matched_at >= window_start,
    )

    if group_value is not None:
        query = query.where(ThresholdMatch.group_value == group_value)
    else:
        query = query.where(ThresholdMatch.group_value.is_(None))

    result = await db.execute(query)
    count = result.scalar() or 0

    # Check if threshold met
    if count >= rule.threshold_count:
        # Clean up matches for this group to prevent repeated alerts
        await cleanup_threshold_matches(db, rule.id, group_value, window_start)
        return True

    return False


async def cleanup_threshold_matches(
    db: AsyncSession,
    rule_id: uuid.UUID,
    group_value: str | None,
    window_start: datetime,
) -> None:
    """Remove threshold matches after alert is created to prevent re-triggering."""
    query = delete(ThresholdMatch).where(
        ThresholdMatch.rule_id == rule_id,
        ThresholdMatch.matched_at >= window_start,
    )

    if group_value is not None:
        query = query.where(ThresholdMatch.group_value == group_value)
    else:
        query = query.where(ThresholdMatch.group_value.is_(None))

    await db.execute(query)


async def cleanup_old_matches(db: AsyncSession, hours: int = 24) -> int:
    """
    Periodic cleanup of old threshold matches.

    Should be called by a scheduled task to prevent table growth.
    Returns the number of deleted rows.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        delete(ThresholdMatch).where(ThresholdMatch.matched_at < cutoff)
    )

    return result.rowcount or 0
