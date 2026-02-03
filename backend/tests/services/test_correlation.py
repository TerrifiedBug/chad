"""Tests for correlation service."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models.correlation_rule import CorrelationRule, CorrelationRuleVersion
from app.models.correlation_state import CorrelationState
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus
from app.services.correlation import (
    check_correlation,
    cleanup_expired_states,
    get_nested_value,
)


class TestGetNestedValue:
    """Tests for get_nested_value helper function."""

    def test_simple_key(self):
        """Test extracting a simple top-level key."""
        doc = {"name": "test"}
        assert get_nested_value(doc, "name") == "test"

    def test_nested_key(self):
        """Test extracting a nested key."""
        doc = {"process": {"executable": "/usr/bin/bash"}}
        assert get_nested_value(doc, "process.executable") == "/usr/bin/bash"

    def test_deeply_nested(self):
        """Test extracting a deeply nested key."""
        doc = {"a": {"b": {"c": {"d": "value"}}}}
        assert get_nested_value(doc, "a.b.c.d") == "value"

    def test_missing_key(self):
        """Test that missing keys return None."""
        doc = {"name": "test"}
        assert get_nested_value(doc, "missing") is None

    def test_missing_nested_key(self):
        """Test that missing nested keys return None."""
        doc = {"process": {"name": "test"}}
        assert get_nested_value(doc, "process.executable") is None

    def test_non_dict_intermediate(self):
        """Test that non-dict intermediates return None."""
        doc = {"process": "not-a-dict"}
        assert get_nested_value(doc, "process.executable") is None


class TestKeywordSuffixStripping:
    """Tests for .keyword and .text suffix stripping in resolve_entity_field."""

    def test_strips_keyword_suffix(self):
        """Test that .keyword suffix is stripped when getting nested value."""
        doc = {"process": {"executable": "/usr/bin/bash"}}
        # Simulate what happens after stripping .keyword
        field = "process.executable.keyword"
        if field.endswith('.keyword'):
            field = field[:-8]
        result = get_nested_value(doc, field)
        assert result == "/usr/bin/bash"

    def test_strips_text_suffix(self):
        """Test that .text suffix is stripped when getting nested value."""
        doc = {"process": {"command_line": "bash -c 'echo test'"}}
        # Simulate what happens after stripping .text
        field = "process.command_line.text"
        if field.endswith('.text'):
            field = field[:-5]
        result = get_nested_value(doc, field)
        assert result == "bash -c 'echo test'"

    def test_no_suffix_unchanged(self):
        """Test that fields without suffixes work normally."""
        doc = {"user": {"name": "admin"}}
        field = "user.name"
        result = get_nested_value(doc, field)
        assert result == "admin"


@pytest.mark.asyncio
async def test_check_correlation_stores_state_on_first_rule(db_session, test_user):
    """Test that check_correlation stores state when first rule fires."""
    # Create minimal required records
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="logs-test-corr-1",
        pattern="logs-*",
        percolator_index="chad-percolator-logs-test-corr-1",
    )
    db_session.add(index_pattern)
    await db_session.flush()

    rule_a = Rule(
        id=uuid.uuid4(),
        title="Rule A",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    rule_b = Rule(
        id=uuid.uuid4(),
        title="Rule B",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    db_session.add_all([rule_a, rule_b])
    await db_session.flush()

    # Correlation rule with deployed version
    corr_rule = CorrelationRule(
        id=uuid.uuid4(),
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        deployed_at=datetime.now(UTC),
        deployed_version=1,
        current_version=1,
        created_by=test_user.id,
    )
    db_session.add(corr_rule)
    await db_session.flush()

    version = CorrelationRuleVersion(
        id=uuid.uuid4(),
        correlation_rule_id=corr_rule.id,
        version_number=1,
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        changed_by=test_user.id,
        change_reason="Initial deployment",
    )
    db_session.add(version)
    await db_session.commit()

    # Mock resolve_entity_field to return a test value
    with patch('app.services.correlation.resolve_entity_field', new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = "/usr/bin/malware"

        log_document = {"process": {"executable": "/usr/bin/malware"}}
        result = await check_correlation(
            db_session,
            rule_id=rule_a.id,
            log_document=log_document,
            alert_id="alert-001",
        )

        # Should return empty (no correlation yet, just storing state)
        assert result == []

        # State should be stored
        await db_session.flush()
        states_result = await db_session.execute(
            select(CorrelationState).where(CorrelationState.correlation_rule_id == corr_rule.id)
        )
        state = states_result.scalar_one_or_none()
        assert state is not None
        assert state.entity_value == "/usr/bin/malware"
        assert state.rule_id == rule_a.id
        assert state.alert_id == "alert-001"


@pytest.mark.asyncio
async def test_check_correlation_triggers_on_second_rule(db_session, test_user):
    """Test that check_correlation triggers when second rule fires within window."""
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="logs-test-corr-2",
        pattern="logs-*",
        percolator_index="chad-percolator-logs-test-corr-2",
    )
    db_session.add(index_pattern)
    await db_session.flush()

    rule_a = Rule(
        id=uuid.uuid4(),
        title="Rule A",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    rule_b = Rule(
        id=uuid.uuid4(),
        title="Rule B",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    db_session.add_all([rule_a, rule_b])
    await db_session.flush()

    corr_rule = CorrelationRule(
        id=uuid.uuid4(),
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="critical",
        deployed_at=datetime.now(UTC),
        deployed_version=1,
        current_version=1,
        created_by=test_user.id,
    )
    db_session.add(corr_rule)
    await db_session.flush()

    version = CorrelationRuleVersion(
        id=uuid.uuid4(),
        correlation_rule_id=corr_rule.id,
        version_number=1,
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="critical",
        changed_by=test_user.id,
        change_reason="Initial deployment",
    )
    db_session.add(version)
    await db_session.flush()

    # Pre-existing state from rule A
    now = datetime.utcnow()
    existing_state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="/usr/bin/malware",
        rule_id=rule_a.id,
        alert_id="alert-001",
        triggered_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(minutes=3),
    )
    db_session.add(existing_state)
    await db_session.commit()

    # Mock resolve_entity_field to return same entity value
    with patch('app.services.correlation.resolve_entity_field', new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = "/usr/bin/malware"

        log_document = {"process": {"executable": "/usr/bin/malware"}}
        result = await check_correlation(
            db_session,
            rule_id=rule_b.id,
            log_document=log_document,
            alert_id="alert-002",
        )

        # Should trigger correlation
        assert len(result) == 1
        assert result[0]["correlation_name"] == "Test Correlation"
        assert result[0]["severity"] == "critical"
        assert result[0]["entity_value"] == "/usr/bin/malware"
        assert result[0]["first_alert_id"] == "alert-001"
        assert result[0]["second_alert_id"] == "alert-002"


@pytest.mark.asyncio
async def test_check_correlation_no_trigger_different_entity(db_session, test_user):
    """Test that correlation doesn't trigger for different entity values."""
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="logs-test-corr-3",
        pattern="logs-*",
        percolator_index="chad-percolator-logs-test-corr-3",
    )
    db_session.add(index_pattern)
    await db_session.flush()

    rule_a = Rule(
        id=uuid.uuid4(),
        title="Rule A",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    rule_b = Rule(
        id=uuid.uuid4(),
        title="Rule B",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    db_session.add_all([rule_a, rule_b])
    await db_session.flush()

    corr_rule = CorrelationRule(
        id=uuid.uuid4(),
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        deployed_at=datetime.now(UTC),
        deployed_version=1,
        current_version=1,
        created_by=test_user.id,
    )
    db_session.add(corr_rule)
    await db_session.flush()

    version = CorrelationRuleVersion(
        id=uuid.uuid4(),
        correlation_rule_id=corr_rule.id,
        version_number=1,
        name="Test Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        changed_by=test_user.id,
        change_reason="Initial deployment",
    )
    db_session.add(version)
    await db_session.flush()

    # State from rule A with DIFFERENT entity
    now = datetime.utcnow()
    existing_state = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="/usr/bin/other",  # Different entity!
        rule_id=rule_a.id,
        alert_id="alert-001",
        triggered_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(minutes=3),
    )
    db_session.add(existing_state)
    await db_session.commit()

    # Mock resolve_entity_field to return different entity value
    with patch('app.services.correlation.resolve_entity_field', new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = "/usr/bin/malware"  # Different from stored state

        log_document = {"process": {"executable": "/usr/bin/malware"}}
        result = await check_correlation(
            db_session,
            rule_id=rule_b.id,
            log_document=log_document,
            alert_id="alert-002",
        )

        # Should NOT trigger - entities don't match
        assert result == []


@pytest.mark.asyncio
async def test_check_correlation_skips_snoozed_rules(db_session, test_user):
    """Test that snoozed correlation rules are skipped."""
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="logs-test-corr-4",
        pattern="logs-*",
        percolator_index="chad-percolator-logs-test-corr-4",
    )
    db_session.add(index_pattern)
    await db_session.flush()

    rule_a = Rule(
        id=uuid.uuid4(),
        title="Rule A",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    rule_b = Rule(
        id=uuid.uuid4(),
        title="Rule B",
        description="Test",
        yaml_content="detection:\n  selection:\n    Image: '*'",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    db_session.add_all([rule_a, rule_b])
    await db_session.flush()

    # Snoozed indefinitely
    corr_rule = CorrelationRule(
        id=uuid.uuid4(),
        name="Snoozed Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        deployed_at=datetime.now(UTC),
        deployed_version=1,
        current_version=1,
        snooze_indefinite=True,  # Snoozed!
        created_by=test_user.id,
    )
    db_session.add(corr_rule)
    await db_session.flush()

    version = CorrelationRuleVersion(
        id=uuid.uuid4(),
        correlation_rule_id=corr_rule.id,
        version_number=1,
        name="Snoozed Correlation",
        rule_a_id=rule_a.id,
        rule_b_id=rule_b.id,
        entity_field="Image",
        time_window_minutes=5,
        severity="high",
        changed_by=test_user.id,
        change_reason="Initial deployment",
    )
    db_session.add(version)
    await db_session.commit()

    # Even with mock returning a value, no state should be stored due to snooze
    with patch('app.services.correlation.resolve_entity_field', new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = "/usr/bin/malware"

        result = await check_correlation(
            db_session,
            rule_id=rule_a.id,
            log_document={},
            alert_id="alert-001",
        )

        assert result == []

        # No state should be stored
        states_result = await db_session.execute(
            select(CorrelationState).where(CorrelationState.correlation_rule_id == corr_rule.id)
        )
        assert states_result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_cleanup_expired_states(db_session, test_user):
    """Test that expired states are cleaned up."""
    # Create minimal required records for foreign key
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="logs-cleanup-test",
        pattern="logs-*",
        percolator_index="chad-percolator-logs-cleanup-test",
    )
    db_session.add(index_pattern)
    await db_session.flush()

    rule = Rule(
        id=uuid.uuid4(),
        title="Cleanup Test Rule",
        description="Test",
        yaml_content="detection:\n  selection:\n    foo: bar",
        severity="medium",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    db_session.add(rule)
    await db_session.flush()

    corr_rule = CorrelationRule(
        id=uuid.uuid4(),
        name="Cleanup Test Correlation",
        rule_a_id=rule.id,
        rule_b_id=rule.id,
        entity_field="foo",
        time_window_minutes=5,
        severity="high",
        created_by=test_user.id,
    )
    db_session.add(corr_rule)
    await db_session.commit()

    now = datetime.utcnow()

    # Expired states
    expired1 = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.1",
        rule_id=rule.id,
        alert_id="alert-1",
        triggered_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    expired2 = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.2",
        rule_id=rule.id,
        alert_id="alert-2",
        triggered_at=now - timedelta(minutes=8),
        expires_at=now - timedelta(minutes=3),
    )
    # Valid state
    valid = CorrelationState(
        correlation_rule_id=corr_rule.id,
        entity_value="192.168.1.3",
        rule_id=rule.id,
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
