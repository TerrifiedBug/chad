"""
Correlation service for detecting multi-rule patterns.

Evaluates correlation rules to detect when multiple rules match
related entities within a specified time window.
"""

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.correlation_rule import CorrelationRule, CorrelationRuleVersion
from app.models.correlation_state import CorrelationState
from app.models.rule import Rule
from app.services.field_mapping import resolve_mappings

logger = logging.getLogger(__name__)


def is_rule_snoozed(corr_rule: CorrelationRule) -> bool:
    """Check if a correlation rule is currently snoozed."""
    if corr_rule.snooze_indefinite:
        return True
    if corr_rule.snooze_until:
        now = datetime.now(UTC)
        # Handle both timezone-aware and timezone-naive datetimes
        snooze_until = corr_rule.snooze_until
        if snooze_until.tzinfo is None:
            snooze_until = snooze_until.replace(tzinfo=UTC)
        return now < snooze_until
    return False


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
    # Strip OpenSearch field type suffixes (.keyword, .text) - these are query hints,
    # not actual document paths
    doc_field = target_field
    if doc_field.endswith('.keyword'):
        doc_field = doc_field[:-8]
    elif doc_field.endswith('.text'):
        doc_field = doc_field[:-5]

    entity_value = get_nested_value(log_document, doc_field)
    if entity_value is None:
        logger.debug(
            f"Field {target_field} (resolved from {sigma_field}) not found in log document"
        )
        return None

    return str(entity_value)


async def get_deployed_version_data(
    db: AsyncSession,
    corr_rule: CorrelationRule,
) -> CorrelationRuleVersion | None:
    """
    Get the deployed version snapshot for a correlation rule.

    Args:
        db: Database session
        corr_rule: The correlation rule

    Returns:
        The deployed version snapshot, or None if not deployed
    """
    if corr_rule.deployed_version is None:
        return None

    result = await db.execute(
        select(CorrelationRuleVersion).where(
            and_(
                CorrelationRuleVersion.correlation_rule_id == corr_rule.id,
                CorrelationRuleVersion.version_number == corr_rule.deployed_version,
            )
        )
    )
    return result.scalar_one_or_none()


async def check_correlation(
    db: AsyncSession,
    rule_id: UUID,
    log_document: dict,
    alert_id: str,
) -> list[dict]:
    """
    Check if this alert triggers any correlation rules.

    Called when a new alert is created. Checks if:
    1. This rule is part of any deployed correlation rules
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

    # Find all deployed correlation rules where this rule is either A or B
    result = await db.execute(
        select(CorrelationRule).where(
            and_(
                CorrelationRule.deployed_at.isnot(None),
                or_(
                    CorrelationRule.rule_a_id == rule_id,
                    CorrelationRule.rule_b_id == rule_id,
                ),
            )
        )
    )
    correlation_rules = result.scalars().all()

    if not correlation_rules:
        logger.debug(f"No deployed correlation rules found involving rule {rule_id}")
        return triggered

    logger.info(f"Checking {len(correlation_rules)} correlation rule(s) for rule {rule_id}")

    # Fetch deployed version data for each correlation rule
    # Create list of (corr_rule, deployed_data) tuples
    # Filter out snoozed rules
    rules_with_deployed_data: list[tuple[CorrelationRule, CorrelationRuleVersion]] = []
    for corr_rule in correlation_rules:
        # Skip snoozed rules
        if is_rule_snoozed(corr_rule):
            logger.debug(f"Correlation rule {corr_rule.id} is snoozed, skipping")
            continue

        deployed_data = await get_deployed_version_data(db, corr_rule)
        if deployed_data is None:
            logger.warning(
                f"Correlation rule {corr_rule.id} has no deployed version data, skipping"
            )
            continue
        rules_with_deployed_data.append((corr_rule, deployed_data))

    # Group correlation rules by sigma_field (from deployed data) to avoid redundant resolution
    # Store as dict: sigma_field -> list of (corr_rule, deployed_data) tuples
    corr_rules_by_field: dict[str, list[tuple[CorrelationRule, CorrelationRuleVersion]]] = {}
    for corr_rule, deployed_data in rules_with_deployed_data:
        sigma_field = deployed_data.entity_field
        if sigma_field not in corr_rules_by_field:
            corr_rules_by_field[sigma_field] = []
        corr_rules_by_field[sigma_field].append((corr_rule, deployed_data))

    # For each unique sigma_field, resolve the entity value and check correlations
    for sigma_field, corr_rules_data in corr_rules_by_field.items():
        # Resolve the Sigma field to an entity value for this rule
        entity_value = await resolve_entity_field(db, rule_id, sigma_field, log_document)
        if not entity_value:
            logger.info(f"Correlation check: Could not resolve entity field '{sigma_field}' for rule {rule_id}")
            continue

        logger.info(f"Correlation check: Resolved '{sigma_field}' to value '{entity_value}' for rule {rule_id}")

        now = datetime.utcnow()

        for corr_rule, deployed_data in corr_rules_data:
            # Determine which rule in the pair just fired and which to wait for
            # Use deployed_data for rule IDs
            if rule_id == deployed_data.rule_a_id:
                paired_rule_id = deployed_data.rule_b_id
            else:
                paired_rule_id = deployed_data.rule_a_id

            # Check for existing state from the paired rule
            # Use deployed_data for time window
            cutoff = now - timedelta(minutes=deployed_data.time_window_minutes)

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
            existing_state = state_result.scalars().first()

            if existing_state:
                # Correlation triggered! Both rules fired within time window
                logger.info(
                    f"Correlation triggered: {corr_rule.name} "
                    f"(sigma_field={sigma_field}, entity={entity_value}, paired_alert={existing_state.alert_id})"
                )

                # Create a correlation alert (this will be stored/processed elsewhere)
                # Use deployed_data for severity and rule IDs
                triggered.append(
                    {
                        "correlation_rule_id": str(corr_rule.id),
                        "correlation_name": corr_rule.name,
                        "severity": deployed_data.severity,
                        "rule_a_id": str(deployed_data.rule_a_id),
                        "rule_b_id": str(deployed_data.rule_b_id),
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
                # Use deployed_data for time window
                expires_at = now + timedelta(minutes=deployed_data.time_window_minutes)
                state = CorrelationState(
                    correlation_rule_id=corr_rule.id,
                    entity_value=entity_value,
                    rule_id=rule_id,
                    alert_id=alert_id,
                    triggered_at=now,
                    expires_at=expires_at,
                )
                db.add(state)
                # Log state storage at INFO level for debugging correlation issues
                logger.info(
                    f"Correlation state stored: rule={corr_rule.name}, waiting for paired rule, "
                    f"entity={entity_value}, expires in {deployed_data.time_window_minutes}m"
                )

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
