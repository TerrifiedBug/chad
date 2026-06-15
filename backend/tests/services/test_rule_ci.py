"""Tests for the Detection-as-Code CI service (app.services.rule_ci)."""

import uuid
from unittest.mock import MagicMock

import pytest

from app.core.security import get_password_hash
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus
from app.models.user import User, UserRole
from app.services.rule_ci import (
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIPPED,
    STATUS_WARN,
    CICheck,
    CIOptions,
    _aggregate,
    _check_coverage,
    _check_lint,
    run_ci,
)

# A minimal valid Sigma rule (no ATT&CK tags) used across several tests.
VALID_RULE = """title: Suspicious Process
logsource:
    category: process_creation
detection:
    selection:
        process.executable|endswith: '.exe'
    condition: selection
level: medium
"""

# A rule with an ATT&CK technique tag for the coverage check.
VALID_RULE_WITH_TAGS = """title: Suspicious Process With Tag
logsource:
    category: process_creation
detection:
    selection:
        process.executable|endswith: '.exe'
    condition: selection
tags:
    - attack.t1059
level: medium
"""

# Missing the required 'detection' section -> should fail linting.
INVALID_RULE = """title: Broken Rule
logsource:
    category: process_creation
"""


# --- _check_lint -----------------------------------------------------------


def test_check_lint_passes_on_valid_rule():
    check, translation = _check_lint(VALID_RULE)
    assert check.name == "lint"
    assert check.status == STATUS_PASS
    assert translation.success is True


def test_check_lint_fails_on_invalid_rule():
    check, translation = _check_lint(INVALID_RULE)
    assert check.name == "lint"
    assert check.status == STATUS_FAIL
    assert translation.success is False
    assert check.data.get("errors")


def test_check_lint_fails_on_garbage_yaml():
    check, _ = _check_lint("not: : : valid: yaml: [")
    assert check.status == STATUS_FAIL


# --- _aggregate ------------------------------------------------------------


def test_aggregate_all_pass():
    report = _aggregate(
        [
            CICheck(name="lint", status=STATUS_PASS, detail="ok"),
            CICheck(name="coverage", status=STATUS_PASS, detail="ok"),
        ]
    )
    assert report.passed is True
    assert "passed" in report.summary.lower()


def test_aggregate_warning_does_not_block():
    report = _aggregate(
        [
            CICheck(name="lint", status=STATUS_PASS, detail="ok"),
            CICheck(name="coverage", status=STATUS_WARN, detail="no techniques"),
        ]
    )
    # A warning is advisory — overall still passes.
    assert report.passed is True
    assert "warning" in report.summary.lower()


def test_aggregate_skip_does_not_block():
    report = _aggregate(
        [
            CICheck(name="lint", status=STATUS_PASS, detail="ok"),
            CICheck(name="fp_backtest", status=STATUS_SKIPPED, detail="no OS"),
        ]
    )
    assert report.passed is True
    assert "skipped" in report.summary.lower()


def test_aggregate_failure_blocks():
    report = _aggregate(
        [
            CICheck(name="lint", status=STATUS_FAIL, detail="bad"),
            CICheck(name="coverage", status=STATUS_WARN, detail="no techniques"),
        ]
    )
    assert report.passed is False
    assert "failed" in report.summary.lower()


# --- _check_coverage (ad-hoc YAML path; no stored rule id) -----------------


@pytest.mark.asyncio
async def test_coverage_warns_without_tags(test_session):
    check = await _check_coverage(test_session, VALID_RULE, rule_id=None)
    assert check.name == "coverage"
    assert check.status == STATUS_WARN


@pytest.mark.asyncio
async def test_coverage_passes_with_tags(test_session):
    check = await _check_coverage(test_session, VALID_RULE_WITH_TAGS, rule_id=None)
    assert check.status == STATUS_PASS
    assert check.data.get("technique_ids") == ["T1059"]


# --- run_ci aggregation with OpenSearch checks degraded to skipped ---------


@pytest.mark.asyncio
async def test_run_ci_valid_rule_no_opensearch(test_session):
    """With os_client=None the OS-dependent checks skip, valid rule passes."""
    report = await run_ci(
        db=test_session,
        os_client=None,
        rule_yaml=VALID_RULE_WITH_TAGS,
        index_pattern_id=None,
    )
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["lint"] == STATUS_PASS
    assert statuses["fp_backtest"] == STATUS_SKIPPED
    assert statuses["coverage"] == STATUS_PASS
    assert report.passed is True


@pytest.mark.asyncio
async def test_run_ci_invalid_rule_fails_and_skips_backtest(test_session):
    """A lint failure blocks the report and skips the backtest entirely."""
    report = await run_ci(
        db=test_session,
        os_client=None,
        rule_yaml=INVALID_RULE,
        index_pattern_id=None,
    )
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["lint"] == STATUS_FAIL
    assert statuses["fp_backtest"] == STATUS_SKIPPED
    assert report.passed is False


@pytest.mark.asyncio
async def test_run_ci_fp_backtest_warns_over_threshold(test_session):
    """Mock OpenSearch so the backtest match count exceeds the threshold."""
    # Index pattern + field mapping so field validation can resolve.
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="ci-logs",
        pattern="ci-logs-*",
        percolator_index=".percolator-ci-logs",
    )
    test_session.add(index_pattern)
    await test_session.commit()

    os_client = MagicMock()
    # get_index_fields reads indices.get_mapping; return the referenced field so
    # field_validation passes, then count returns a noisy number.
    os_client.indices.get_mapping.return_value = {
        "ci-logs-001": {
            "mappings": {"properties": {"process": {"properties": {"executable": {"type": "keyword"}}}}}
        }
    }
    os_client.count.return_value = {"count": 5000}

    report = await run_ci(
        db=test_session,
        os_client=os_client,
        rule_yaml=VALID_RULE_WITH_TAGS,
        index_pattern_id=index_pattern.id,
        options=CIOptions(fp_threshold=1000),
    )
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["fp_backtest"] == STATUS_WARN
    # A warning does not block the overall pass.
    assert report.passed is True
    backtest = next(c for c in report.checks if c.name == "fp_backtest")
    assert backtest.data["match_count"] == 5000


@pytest.mark.asyncio
async def test_run_ci_field_validation_fails_on_unmapped_field(test_session):
    """When the index has no matching field and there's no mapping, fail."""
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="ci-empty",
        pattern="ci-empty-*",
        percolator_index=".percolator-ci-empty",
    )
    test_session.add(index_pattern)
    await test_session.commit()

    os_client = MagicMock()
    # Index has an unrelated field -> the rule's field is unmapped.
    os_client.indices.get_mapping.return_value = {
        "ci-empty-001": {"mappings": {"properties": {"unrelated": {"type": "keyword"}}}}
    }
    os_client.count.return_value = {"count": 0}

    report = await run_ci(
        db=test_session,
        os_client=os_client,
        rule_yaml=VALID_RULE,
        index_pattern_id=index_pattern.id,
    )
    field_check = next(c for c in report.checks if c.name == "field_validation")
    assert field_check.status == STATUS_FAIL
    assert "process.executable" in field_check.data["unmapped_fields"]
    assert report.passed is False


@pytest.mark.asyncio
async def test_run_ci_stored_rule_coverage_from_db(test_session):
    """A stored rule with persisted ATT&CK mappings passes coverage via the DB."""
    from app.models.attack_technique import AttackTechnique, RuleAttackMapping

    user = User(
        id=uuid.uuid4(),
        email=f"ci-{uuid.uuid4()}@example.com",
        password_hash=get_password_hash("pw-12345678"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="ci-stored",
        pattern="ci-stored-*",
        percolator_index=".percolator-ci-stored",
    )
    test_session.add_all([user, index_pattern])
    await test_session.flush()

    rule = Rule(
        id=uuid.uuid4(),
        title="Stored CI Rule",
        description="desc",
        yaml_content=VALID_RULE,  # no tags in YAML — coverage must come from DB
        severity="medium",
        status=RuleStatus.UNDEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=index_pattern.id,
        created_by=user.id,
    )
    technique = AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        tactic_name="Execution",
    )
    test_session.add_all([rule, technique])
    await test_session.flush()
    test_session.add(RuleAttackMapping(rule_id=rule.id, technique_id="T1059"))
    await test_session.commit()

    check = await _check_coverage(test_session, VALID_RULE, rule_id=rule.id)
    assert check.status == STATUS_PASS
    assert check.data["technique_count"] == 1
