"""
Correlation service for detecting multi-rule patterns.

Evaluates correlation rules to detect when multiple rules match
related entities within a specified time window.
"""

import logging
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.correlation_rule import CorrelationRule
from app.models.correlation_state import CorrelationState
from app.models.rule import Rule
from app.services.field_mapping import resolve_field_mappings

logger = logging.getLogger(__name__)


def get_nested_value(obj: dict, path: str) -> any:
    """Get a value from a nested dict using dot notation."""
    keys = path.split('.')
    value = obj
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value


async def check_correlation(
    db: AsyncSession,
    rule_id: UUID,
    entity_field: str,
    entity_value: str,
    log_document: dict,
) -> list[dict]:
    """
    Check if this alert triggers any correlation rules.

    Called when a new alert is created. Checks if:
    1. This rule is part of any enabled correlation rules
    2. There's an existing matching state entry from the paired rule
    3. The match is within the time window

    The entity_field is resolved through field mappings for each rule,
    allowing correlation across different index patterns with different field names.

    Args:
        db: Database session
        rule_id: The rule that just fired
        entity_field: Field name to extract entity from (e.g., "source.ip")
        entity_value: Value of the entity field (e.g., "192.168.1.100")
        log_document: Original log document for context

    Returns:
        List of triggered correlations with details
    """
    triggered = []

    # Find all correlation rules where this rule is either A or B
    result = await db.execute(
        select(CorrelationRule).where(
            and_(
                CorrelationRule.is_enabled == True,
                or_(
                    CorrelationRule.rule_a_id == rule_id,
                    CorrelationRule.rule_b_id == rule_id,
                ),
            )
        )
    )
    correlation_rules = result.scalars().all()

    for corr_rule in correlation_rules:
        # Determine which rule in the pair just fired and which to wait for
        if rule_id == corr_rule.rule_a_id:
            paired_rule_id = corr_rule.rule_b_id
        else:
            paired_rule_id = corr_rule.rule_a_id

        # Check for existing state from the paired rule
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=corr_rule.time_window_minutes)

        state_result = await db.execute(
            select(CorrelationState).where(
                and_(
                    CorrelationState.correlation_rule_id == corr_rule.id,
                    CorrelationState.entity_value == entity_value,
                    CorrelationState.rule_id == paired_rule_id,
                    CorrelationState.expires_at > cutoff,
                )
            )
        )
        existing_state = state_result.first()

        if existing_state:
            # Correlation triggered! Both rules fired within time window
            logger.info(
                f"Correlation triggered: {corr_rule.name} "
                f"(entity={entity_value}, paired_alert={existing_state.alert_id})"
            )

            # Create a correlation alert (this will be stored/processed elsewhere)
            triggered.append(
                {
                    "correlation_rule_id": str(corr_rule.id),
                    "correlation_name": corr_rule.name,
                    "severity": corr_rule.severity,
                    "rule_a_id": str(corr_rule.rule_a_id),
                    "rule_b_id": str(corr_rule.rule_b_id),
                    "entity_field": entity_field,
                    "entity_value": entity_value,
                    "first_alert_id": existing_state.alert_id,
                    "second_alert_id": None,  # Will be filled in by caller
                    "first_triggered_at": existing_state.triggered_at.isoformat(),
                    "second_triggered_at": now.isoformat(),
                }
            )

            # Clean up the used state entry
            await db.delete(existing_state)
        else:
            # No match yet, store this event for future correlation
            expires_at = now + timedelta(minutes=corr_rule.time_window_minutes)
            state = CorrelationState(
                correlation_rule_id=corr_rule.id,
                entity_value=entity_value,
                rule_id=rule_id,
                alert_id="",  # Will be filled in by caller
                triggered_at=now,
                expires_at=expires_at,
            )
            db.add(state)
            logger.debug(f"Stored correlation state for {corr_rule.name}, entity={entity_value}")

    return triggered


async def cleanup_expired_states(db: AsyncSession) -> int:
    """
    Clean up expired correlation state entries.

    Should be run periodically (e.g., every 5 minutes) to prevent
    the correlation_state table from growing indefinitely.

    Args:
        db: Database session

    Returns:
        Number of states cleaned up
    """
    now = datetime.utcnow()

    result = await db.execute(
        select(CorrelationState).where(CorrelationState.expires_at < now)
    )
    expired_states = result.scalars().all()

    count = len(expired_states)
    for state in expired_states:
        await db.delete(state)

    if count > 0:
        logger.info(f"Cleaned up {count} expired correlation states")

    return count
