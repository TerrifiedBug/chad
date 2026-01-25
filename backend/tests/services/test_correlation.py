"""Tests for correlation service."""

import uuid
import pytest
from datetime import datetime, timedelta

from app.services.correlation import check_correlation, cleanup_expired_states
from app.models.correlation_rule import CorrelationRule
from app.models.correlation_state import CorrelationState


@pytest.mark.asyncio
async def test_check_correlation_no_existing_state(db_session):
    """Test check_correlation stores state when no prior match exists."""
    rule_a_id = uuid.uuid4()
    rule_b_id = uuid.uuid4()
    corr_rule = CorrelationRule(
        name="Test Correlation",
        rule_a_id=rule_a_id,
        rule_b_id=rule_b_id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(corr_rule)
    await db_session.commit()

    # First rule fires - should store state
    result = await check_correlation(
        db_session,
        rule_id=rule_a_id,
        entity_field="source.ip",
        entity_value="192.168.1.100",
        log_document={},
    )

    assert result == []
    # Check that state was stored
    states = await db_session.execute(
        select(CorrelationState).where(CorrelationState.correlation_rule_id == corr_rule.id)
    )
    assert states.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_check_correlation_triggers_on_match(db_session):
    """Test correlation triggers when both rules match within time window."""
    rule_a_id = uuid.uuid4()
    rule_b_id = uuid.uuid4()
    now = datetime.utcnow()

    corr_rule = CorrelationRule(
        name="Test Correlation",
        rule_a_id=rule_a_id,
        rule_b_id=rule_b_id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(corr_rule)
    await db_session.commit()

    # Store state from rule A
    existing_state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.100",
        rule_id=rule_a_id,
        alert_id="alert-123",
        triggered_at=now - timedelta(minutes=2),  # 2 minutes ago
        expires_at=now + timedelta(minutes=3),  # Expires in 3 minutes
    )
    db_session.add(existing_state)
    await db_session.commit()

    # Rule B fires with same entity - should trigger correlation
    result = await check_correlation(
        db_session,
        rule_id=rule_b_id,
        entity_field="source.ip",
        entity_value="192.168.1.100",
        log_document={},
    )

    assert len(result) == 1
    assert result[0]["correlation_name"] == "Test Correlation"
    assert result[0]["entity_value"] == "192.168.1.100"
    assert result[0]["first_alert_id"] == "alert-123"
    assert result[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_check_correlation_misses_when_expired(db_session):
    """Test correlation doesn't trigger when state is expired."""
    rule_a_id = uuid.uuid4()
    rule_b_id = uuid.uuid4()
    now = datetime.utcnow()

    corr_rule = CorrelationRule(
        name="Test Correlation",
        rule_a_id=rule_a_id,
        rule_b_id=rule_b_id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(corr_rule)
    await db_session.commit()

    # Store expired state from rule A (10 minutes ago, window is 5 minutes)
    existing_state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.100",
        rule_id=rule_a_id,
        alert_id="alert-123",
        triggered_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),  # Already expired
    )
    db_session.add(existing_state)
    await db_session.commit()

    # Rule B fires - should NOT trigger because state is expired
    result = await check_correlation(
        db_session,
        rule_id=rule_b_id,
        entity_field="source.ip",
        entity_value="192.168.1.100",
        log_document={},
    )

    assert len(result) == 0


@pytest.mark.asyncio
async def test_cleanup_expired_states(db_session):
    """Test expired states are cleaned up."""
    now = datetime.utcnow()
    corr_rule_id = uuid.uuid4()
    rule_id = uuid.uuid4()

    # Add some states (mix of expired and not)
    expired1 = CorrelationState(
        correlation_rule_id=corr_rule_id,
        entity_value="192.168.1.1",
        rule_id=rule_id,
        alert_id="alert-1",
        triggered_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    expired2 = CorrelationState(
        correlation_rule_id=corr_rule_id,
        entity_value="192.168.1.2",
        rule_id=rule_id,
        alert_id="alert-2",
        triggered_at=now - timedelta(minutes=8),
        expires_at=now - timedelta(minutes=3),
    )
    valid = CorrelationState(
        correlation_rule_id=corr_rule_id,
        entity_value="192.168.1.3",
        rule_id=rule_id,
        alert_id="alert-3",
        triggered_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=4),
    )

    db_session.add_all([expired1, expired2, valid])
    await db_session.commit()

    # Run cleanup
    count = await cleanup_expired_states(db_session)
    await db_session.commit()

    assert count == 2

    # Verify only valid state remains
    result = await db_session.execute(select(CorrelationState))
    states = result.scalars().all()
    assert len(states) == 1
    assert states[0].alert_id == "alert-3"
