"""Tests for the coverage-gap rule recommendation service (Feature F6)."""

import uuid
from unittest.mock import patch

import pytest

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.field_mapping import FieldMapping, MappingOrigin
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus
from app.services.coverage_recommendations import recommend


async def _seed_techniques(session):
    """Two parent techniques in different tactics + a covered one."""
    techs = [
        AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",  # Execution (high prevalence)
            tactic_name="Execution",
            is_subtechnique=False,
        ),
        AttackTechnique(
            id="T1566",
            name="Phishing",
            tactic_id="TA0001",  # Initial Access (lower prevalence)
            tactic_name="Initial Access",
            is_subtechnique=False,
        ),
        AttackTechnique(
            id="T1003",
            name="OS Credential Dumping",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            is_subtechnique=False,
        ),
        # A sub-technique that must NOT appear as a standalone recommendation.
        AttackTechnique(
            id="T1059.001",
            name="PowerShell",
            tactic_id="TA0002",
            tactic_name="Execution",
            parent_id="T1059",
            is_subtechnique=True,
        ),
    ]
    for t in techs:
        session.add(t)
    await session.commit()


async def _make_index_pattern(session):
    ip = IndexPattern(
        id=uuid.uuid4(),
        name="logs-rec",
        pattern="logs-rec-*",
        percolator_index=".percolator-logs-rec",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_deployed_rule(session, ip, user, title, technique_id):
    """Create a DEPLOYED rule mapped to a technique (gives it coverage)."""
    rule = Rule(
        id=uuid.uuid4(),
        title=title,
        yaml_content="detection:\n  selection:\n    foo: bar\n  condition: selection",
        severity="high",
        status=RuleStatus.DEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=ip.id,
        created_by=user.id,
    )
    session.add(rule)
    await session.flush()
    session.add(RuleAttackMapping(rule_id=rule.id, technique_id=technique_id))
    await session.commit()
    return rule


@pytest.mark.asyncio
async def test_uncovered_techniques_are_surfaced(test_session, test_user):
    """Techniques with no deployed coverage become recommendations; a fully
    covered technique is excluded."""
    await _seed_techniques(test_session)
    ip = await _make_index_pattern(test_session)
    # Give T1003 two deployed rules so it is NOT a gap.
    await _make_deployed_rule(test_session, ip, test_user, "Cred Dump A", "T1003")
    await _make_deployed_rule(test_session, ip, test_user, "Cred Dump B", "T1003")

    # No SigmaHQ repo available in test env -> no candidate rules, but gaps must
    # still be detected from coverage data alone.
    with patch(
        "app.services.coverage_recommendations.sigmahq_service.is_repo_cloned",
        return_value=False,
    ):
        recs = await recommend(test_session, None, limit=10)

    rec_ids = {r.technique_id for r in recs}
    # Uncovered parent techniques are surfaced...
    assert "T1059" in rec_ids
    assert "T1566" in rec_ids
    # ...the well-covered one is not...
    assert "T1003" not in rec_ids
    # ...and the sub-technique is never recommended standalone.
    assert "T1059.001" not in rec_ids


@pytest.mark.asyncio
async def test_recommendations_ranked_by_prevalence(test_session, test_user):
    """With no SigmaHQ candidates, a higher-prevalence tactic outranks a lower
    one (Execution TA0002 > Initial Access TA0001)."""
    await _seed_techniques(test_session)

    with patch(
        "app.services.coverage_recommendations.sigmahq_service.is_repo_cloned",
        return_value=False,
    ):
        recs = await recommend(test_session, None, limit=10)

    order = [r.technique_id for r in recs]
    assert order.index("T1059") < order.index("T1566")
    # Priorities are real numbers and monotonically non-increasing.
    priorities = [r.priority for r in recs]
    assert priorities == sorted(priorities, reverse=True)


@pytest.mark.asyncio
async def test_compatible_sigmahq_rules_boost_priority_and_reason(test_session, test_user):
    """A SigmaHQ rule whose fields the org already maps is flagged compatible,
    boosts the gap's priority, and is reflected in the reason string."""
    await _seed_techniques(test_session)
    ip = await _make_index_pattern(test_session)

    # Org maps "Image" and "CommandLine" -> a rule using only those is compatible.
    for sigma_field in ("Image", "CommandLine"):
        test_session.add(
            FieldMapping(
                id=uuid.uuid4(),
                index_pattern_id=ip.id,
                sigma_field=sigma_field,
                target_field=sigma_field.lower(),
                origin=MappingOrigin.MANUAL,
                created_by=test_user.id,
            )
        )
    await test_session.commit()

    compatible_yaml = (
        "title: PowerShell Spawn\n"
        "detection:\n"
        "  selection:\n"
        "    Image|endswith: powershell.exe\n"
        "    CommandLine|contains: -enc\n"
        "  condition: selection\n"
    )

    def fake_search(query, limit=100, rule_type=None):
        # Only return a hit for the T1059 tag, and only from the detection dir
        # so we get exactly one candidate.
        from app.services.sigmahq import RuleType

        if "t1059" in query.lower() and rule_type == RuleType.DETECTION:
            return [
                {
                    "title": "PowerShell Spawn",
                    "severity": "high",
                    "path": "windows/process_creation/ps_spawn.yml",
                    "tags": ["attack.t1059"],
                }
            ]
        return []

    with patch(
        "app.services.coverage_recommendations.sigmahq_service.is_repo_cloned",
        return_value=True,
    ), patch(
        "app.services.coverage_recommendations.sigmahq_service.search_rules",
        side_effect=fake_search,
    ), patch(
        "app.services.coverage_recommendations.sigmahq_service.get_rule_content",
        return_value=compatible_yaml,
    ):
        recs = await recommend(test_session, None, limit=10)

    by_id = {r.technique_id for r in recs}
    assert "T1059" in by_id

    t1059 = next(r for r in recs if r.technique_id == "T1059")
    assert "PowerShell Spawn" in t1059.suggested_rule_titles
    assert any(sr.compatible for sr in t1059.suggested_rules)
    assert "ready to deploy" in t1059.reason

    # The compatible-rule gap (T1059) must outrank a same-deployment gap that has
    # no candidate rules (T1566).
    t1566 = next(r for r in recs if r.technique_id == "T1566")
    assert t1059.priority > t1566.priority


@pytest.mark.asyncio
async def test_no_techniques_returns_empty(test_session, test_user):
    """No cached ATT&CK techniques -> empty list, no errors."""
    with patch(
        "app.services.coverage_recommendations.sigmahq_service.is_repo_cloned",
        return_value=False,
    ):
        recs = await recommend(test_session, None, limit=10)
    assert recs == []


@pytest.mark.asyncio
async def test_limit_is_respected(test_session, test_user):
    """The limit argument caps the number of recommendations returned."""
    await _seed_techniques(test_session)

    with patch(
        "app.services.coverage_recommendations.sigmahq_service.is_repo_cloned",
        return_value=False,
    ):
        recs = await recommend(test_session, None, limit=1)
    assert len(recs) == 1
