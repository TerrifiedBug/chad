"""Tests for health metrics and ATT&CK coverage functionality."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus
from app.services.attack_coverage import attack_coverage_service
from app.services.health import get_alert_count


class TestAlertCountQueries:
    """Tests for alert count queries in health monitoring."""

    def test_get_alert_count_uses_created_at_field(self):
        """Verify get_alert_count queries the created_at field, not @timestamp."""
        # Mock OpenSearch client
        mock_os = MagicMock()

        # Mock the count response
        mock_os.count.return_value = {"count": 42}

        # Call get_alert_count
        since = datetime.now(UTC) - timedelta(hours=24)
        count = get_alert_count(mock_os, "chad-alerts-*", since)

        # Verify the count was returned
        assert count == 42

        # Verify OpenSearch count was called
        mock_os.count.assert_called_once()

        # Get the query that was passed
        call_args = mock_os.count.call_args
        query_body = call_args[1][1]  # Second positional arg is the body dict

        # Verify it queries created_at, not @timestamp
        assert "query" in query_body
        assert "range" in query_body["query"]
        assert "created_at" in query_body["query"]["range"]
        assert "@timestamp" not in query_body["query"]["range"]

    def test_get_alert_count_uses_naive_datetime(self):
        """Verify get_alert_count strips timezone info for OpenSearch compatibility."""
        mock_os = MagicMock()
        mock_os.count.return_value = {"count": 42}

        # Use timezone-aware datetime
        since_aware = datetime.now(UTC) - timedelta(hours=24)

        # Call get_alert_count
        get_alert_count(mock_os, "chad-alerts-*", since_aware)

        # Verify the query uses naive datetime (no timezone suffix)
        call_args = mock_os.count.call_args
        query_body = call_args[1][1]
        gte_value = query_body["query"]["range"]["created_at"]["gte"]

        # Naive datetime doesn't have +00:00 suffix
        assert "+" not in gte_value
        assert "Z" not in gte_value or gte_value.endswith("Z")  # Could end with Z but no +


class TestAttackCoverageSubtechniqueAggregation:
    """Tests for sub-technique aggregation in coverage API."""

    @pytest.mark.asyncio
    async def test_coverage_aggregates_subtechnique_counts_to_parent(
        self, test_session, test_user
    ):
        """Verify that sub-technique rule counts aggregate to parent technique."""
        # Create parent and sub-technique
        parent_technique = AttackTechnique(
            id="T1053",
            name="Scheduled Task/Job",
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            is_subtechnique=False,
        )
        sub_technique = AttackTechnique(
            id="T1053.002",
            name="At",
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            parent_id="T1053",
            is_subtechnique=True,
        )
        test_session.add_all([parent_technique, sub_technique])

        # Create index pattern and rule
        pattern = IndexPattern(
            name="test-coverage-pattern",
            pattern="test-coverage-*",
            percolator_index="percolator-test-coverage",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)

        rule = Rule(
            id=uuid.uuid4(),
            title="Test Coverage Rule",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        test_session.add(rule)
        await test_session.commit()

        # Create mapping to sub-technique
        mapping = RuleAttackMapping(
            rule_id=rule.id,
            technique_id="T1053.002",
        )
        test_session.add(mapping)
        await test_session.commit()

        # Get coverage
        coverage = await attack_coverage_service.get_coverage(test_session)

        # Parent technique should show the aggregated count
        parent_coverage = coverage.coverage.get("T1053")
        assert parent_coverage is not None
        assert parent_coverage.total == 1  # Aggregated from sub-technique

        # Sub-technique should also show its count
        sub_coverage = coverage.coverage.get("T1053.002")
        assert sub_coverage is not None
        assert sub_coverage.total == 1

    @pytest.mark.asyncio
    async def test_coverage_counts_multiple_subtechniques_aggregate_correctly(
        self, test_session, test_user
    ):
        """Verify multiple sub-techniques all aggregate to parent."""
        # Create parent and multiple sub-techniques
        parent = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
        )
        sub1 = AttackTechnique(
            id="T1059.001",
            name="PowerShell",
            tactic_id="TA0002",
            tactic_name="Execution",
            parent_id="T1059",
            is_subtechnique=True,
        )
        sub2 = AttackTechnique(
            id="T1059.002",
            name="Windows Command Shell",
            tactic_id="TA0002",
            tactic_name="Execution",
            parent_id="T1059",
            is_subtechnique=True,
        )
        test_session.add_all([parent, sub1, sub2])

        # Create index pattern and rules
        pattern = IndexPattern(
            name="test-multi-sub-pattern",
            pattern="test-multi-*",
            percolator_index="percolator-test-multi",
        )
        test_session.add(pattern)
        await test_session.commit()

        rule1 = Rule(
            id=uuid.uuid4(),
            title="Rule 1",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        rule2 = Rule(
            id=uuid.uuid4(),
            title="Rule 2",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        test_session.add_all([rule1, rule2])
        await test_session.commit()

        # Map rules to sub-techniques
        mapping1 = RuleAttackMapping(rule_id=rule1.id, technique_id="T1059.001")
        mapping2 = RuleAttackMapping(rule_id=rule2.id, technique_id="T1059.002")
        test_session.add_all([mapping1, mapping2])
        await test_session.commit()

        # Get coverage
        coverage = await attack_coverage_service.get_coverage(test_session)

        # Parent should show aggregated count (2 rules across sub-techniques)
        parent_coverage = coverage.coverage.get("T1059")
        assert parent_coverage is not None
        assert parent_coverage.total == 2

        # Each sub-technique shows its individual count
        sub1_coverage = coverage.coverage.get("T1059.001")
        assert sub1_coverage is not None
        assert sub1_coverage.total == 1

        sub2_coverage = coverage.coverage.get("T1059.002")
        assert sub2_coverage is not None
        assert sub2_coverage.total == 1

    @pytest.mark.asyncio
    async def test_coverage_direct_parent_mapping_still_counted(
        self, test_session, test_user
    ):
        """Verify direct parent technique mappings are counted, not just sub-techniques."""
        # Create parent technique
        parent = AttackTechnique(
            id="T1053",
            name="Scheduled Task/Job",
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            is_subtechnique=False,
        )
        sub = AttackTechnique(
            id="T1053.002",
            name="At",
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            parent_id="T1053",
            is_subtechnique=True,
        )
        test_session.add_all([parent, sub])

        # Create index pattern and rules
        pattern = IndexPattern(
            name="test-direct-parent-pattern",
            pattern="test-direct-*",
            percolator_index="percolator-test-direct",
        )
        test_session.add(pattern)
        await test_session.commit()

        rule1 = Rule(
            id=uuid.uuid4(),
            title="Rule 1",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        rule2 = Rule(
            id=uuid.uuid4(),
            title="Rule 2",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        test_session.add_all([rule1, rule2])
        await test_session.commit()

        # Map one rule to parent, one to sub-technique
        mapping1 = RuleAttackMapping(rule_id=rule1.id, technique_id="T1053")
        mapping2 = RuleAttackMapping(rule_id=rule2.id, technique_id="T1053.002")
        test_session.add_all([mapping1, mapping2])
        await test_session.commit()

        # Get coverage
        coverage = await attack_coverage_service.get_coverage(test_session)

        # Parent should show count of 2 (direct mapping + sub-technique aggregation)
        parent_coverage = coverage.coverage.get("T1053")
        assert parent_coverage is not None
        assert parent_coverage.total == 2

        # Sub-technique shows its count
        sub_coverage = coverage.coverage.get("T1053.002")
        assert sub_coverage is not None
        assert sub_coverage.total == 1
