"""Tests for correlation rule models."""

import uuid
import pytest
from datetime import datetime, timedelta

from app.models.correlation_rule import CorrelationRule
from app.models.correlation_state import CorrelationState


@pytest.mark.asyncio
async def test_correlation_rule_creation(db_session):
    """Test CorrelationRule model."""
    rule_a_id = uuid.uuid4()
    rule_b_id = uuid.uuid4()

    rule = CorrelationRule(
        name="Brute Force Success",
        rule_a_id=rule_a_id,
        rule_b_id=rule_b_id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
        is_enabled=True,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    assert rule.name == "Brute Force Success"
    assert rule.time_window_minutes == 5
    assert rule.entity_field == "source.ip"
    assert rule.rule_a_id == rule_a_id
    assert rule.rule_b_id == rule_b_id


@pytest.mark.asyncio
async def test_correlation_state_creation(db_session):
    """Test CorrelationState model."""
    rule_a_id = uuid.uuid4()
    rule_b_id = uuid.uuid4()
    now = datetime.utcnow()

    # First create a correlation rule
    corr_rule = CorrelationRule(
        name="Test Correlation",
        rule_a_id=rule_a_id,
        rule_b_id=rule_b_id,
        entity_field="source.ip",
        time_window_minutes=5,
        severity="high",
    )
    db_session.add(corr_rule)
    await db_session.flush()

    state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.100",
        rule_id=rule_a_id,
        alert_id="alert-123",
        triggered_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    db_session.add(state)
    await db_session.commit()
    await db_session.refresh(state)

    assert state.entity_value == "192.168.1.100"
    assert state.expires_at > state.triggered_at
