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
from app.services.field_mapping import resolve_mappings

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


async def resolve_entity_field(
    db: AsyncSession,
    rule_id: UUID,
    sigma_field: str,
    log_document: dict,
) -> str | None:
    """
    Resolve a Sigma field to an entity value from the log document.

    This function:
    1. Loads the rule to get its index pattern
    2. Resolves the Sigma field to the actual log field using field mappings
    3. Extracts the entity value from the log document

    Args:
        db: Database session
        rule_id: The rule ID
        sigma_field: The Sigma field name (e.g., "UserName")
        log_document: The log document to extract from

    Returns:
        The entity value, or None if not found
    """
    # Load the rule with its index pattern
    result = await db.execute(
        select(Rule).options(selectinload(Rule.index_pattern)).where(Rule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule or not rule.index_pattern:
        logger.warning(f"Rule {rule_id} has no index pattern, cannot resolve field {sigma_field}")
        return None

    # Resolve the Sigma field to the actual log field
    mappings = await resolve_mappings(
        db,
        sigma_fields=[sigma_field],
        index_pattern_id=rule.index_pattern_id,
    )
    target_field = mappings.get(sigma_field)

    if not target_field:
        logger.warning(
            f"Sigma field {sigma_field} has no mapping for rule {rule_id} "
            f"(index pattern {rule.index_pattern_id})"
        )
        return None

    # Extract the entity value from the log document
    entity_value = get_nested_value(log_document, target_field)
    if entity_value is None:
        logger.debug(
            f"Field {target_field} (resolved from {sigma_field}) not found in log document"
        )
        return None

    return str(entity_value)


async def check_correlation(
    db: AsyncSession,
    rule_id: UUID,
    log_document: dict,
    alert_id: str,
) -> list[dict]:
    """
    Check if this alert triggers any correlation rules.

    Called when a new alert is created. Checks if:
    1. This rule is part of any enabled correlation rules
    2. There's an existing matching state entry from the paired rule
    3. The match is within the time window

    The sigma_field from each correlation rule is resolved through field mappings,
    allowing correlation across different index patterns with different field names.

    Args:
        db: Database session
        rule_id: The rule that just fired
        log_document: Original log document for context
        alert_id: The ID of the alert that was just created

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

    # Group correlation rules by sigma_field to avoid redundant resolution
    # Store as dict: sigma_field -> list of correlation rules
    corr_rules_by_field: dict[str, list[CorrelationRule]] = {}
    for corr_rule in correlation_rules:
        sigma_field = corr_rule.entity_field
        if sigma_field not in corr_rules_by_field:
            corr_rules_by_field[sigma_field] = []
        corr_rules_by_field[sigma_field].append(corr_rule)

    # For each unique sigma_field, resolve the entity value and check correlations
    for sigma_field, corr_rules in corr_rules_by_field.items():
        # Resolve the Sigma field to an entity value for this rule
        entity_value = await resolve_entity_field(db, rule_id, sigma_field, log_document)
        if not entity_value:
            logger.debug(f"Could not resolve entity field {sigma_field} for rule {rule_id}")
            continue

        now = datetime.utcnow()

        for corr_rule in corr_rules:
            # Determine which rule in the pair just fired and which to wait for
            if rule_id == corr_rule.rule_a_id:
                paired_rule_id = corr_rule.rule_b_id
            else:
                paired_rule_id = corr_rule.rule_a_id

            # Check for existing state from the paired rule
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
                    f"(sigma_field={sigma_field}, entity={entity_value}, paired_alert={existing_state.alert_id})"
                )

                # Create a correlation alert (this will be stored/processed elsewhere)
                triggered.append(
                    {
                        "correlation_rule_id": str(corr_rule.id),
                        "correlation_name": corr_rule.name,
                        "severity": corr_rule.severity,
                        "rule_a_id": str(corr_rule.rule_a_id),
                        "rule_b_id": str(corr_rule.rule_b_id),
                        "sigma_field": sigma_field,
                        "entity_value": entity_value,
                        "first_alert_id": existing_state.alert_id,
                        "second_alert_id": alert_id,
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
                    alert_id=alert_id,
                    triggered_at=now,
                    expires_at=expires_at,
                )
                db.add(state)
                logger.debug(f"Stored correlation state for {corr_rule.name}, sigma_field={sigma_field}, entity={entity_value}")

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
