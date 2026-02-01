"""Tests for correlation rule models."""

from datetime import UTC, datetime, timedelta

import pytest

from app.models.correlation_rule import CorrelationRule
from app.models.correlation_state import CorrelationState


@pytest.mark.asyncio
async def test_correlation_rule_creation(db_session, sample_rules):
    """Test CorrelationRule model creation with valid foreign keys."""
    rule = CorrelationRule(
        name="Brute Force Success",
        rule_a_id=sample_rules[0].id,
        rule_b_id=sample_rules[1].id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    assert rule.name == "Brute Force Success"
    assert rule.time_window_minutes == 5
    assert rule.entity_field == "source.ip"
    assert rule.rule_a_id == sample_rules[0].id
    assert rule.rule_b_id == sample_rules[1].id


@pytest.mark.asyncio
async def test_correlation_state_creation(db_session, sample_rules):
    """Test CorrelationState model."""
    now = datetime.now(UTC)

    # First create a correlation rule
    corr_rule = CorrelationRule(
        name="Test Correlation",
        rule_a_id=sample_rules[0].id,
        rule_b_id=sample_rules[1].id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(corr_rule)
    await db_session.flush()

    state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.100",
        rule_id=sample_rules[0].id,
        alert_id="alert-123",
        triggered_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    db_session.add(state)
    await db_session.commit()
    await db_session.refresh(state)

    assert state.entity_value == "192.168.1.100"
    assert state.expires_at > state.triggered_at
