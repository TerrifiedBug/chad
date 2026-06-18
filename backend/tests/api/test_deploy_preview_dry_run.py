"""Tests for the deploy-preview historical dry-run (blast radius) wiring."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.api.deps import get_opensearch_client_optional
from app.core.security import create_access_token, get_password_hash
from app.main import app
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.services.rule_testing import HistoricalTestResult

# Minimal Sigma rule that translates cleanly (one field: fieldA).
_VALID_YAML = (
    "title: {title}\nlogsource:\n  category: test\n"
    "detection:\n  selection:\n    fieldA: value\n  condition: selection\n"
)


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _seed_opensearch(session) -> None:
    session.add(
        Setting(key="opensearch", value={"host": "localhost", "port": 9200,
                                         "use_ssl": False, "verify_certs": False})
    )
    await session.commit()


async def _make_pull_pattern(session) -> IndexPattern:
    ip = IndexPattern(
        id=uuid.uuid4(), name="dry-run", pattern="dry-run-*",
        percolator_index=".perc-dry-run", mode="pull",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_rule(session, ip, user, title="Dry Rule"):
    rule = Rule(
        id=uuid.uuid4(), title=title, yaml_content=_VALID_YAML.format(title=title),
        severity="low", status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
        index_pattern_id=ip.id, created_by=user.id,
    )
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=1,
                            yaml_content=_VALID_YAML.format(title=title),
                            changed_by=user.id, change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


@pytest.mark.asyncio
async def test_dry_run_populated_from_historical_test(
    client, test_session, admin_user, monkeypatch
):
    """When OpenSearch + index pattern are present, dry_run carries the
    scanned/matches/truncated summary from run_historical_test."""
    await _seed_opensearch(test_session)
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )

    captured: dict = {}

    async def _fake_historical(*, db, os_client, rule_id, start_date, end_date, limit):
        captured["limit"] = limit
        captured["start_date"] = start_date
        captured["end_date"] = end_date
        return HistoricalTestResult(
            total_scanned=1000, total_matches=42, matches=[], truncated=True,
        )

    monkeypatch.setattr(
        "app.api.rules.testing.run_historical_test", _fake_historical
    )

    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user)

    app.dependency_overrides[get_opensearch_client_optional] = lambda: MagicMock()
    try:
        resp = await client.get(
            f"/api/rules/{rule.id}/deploy-preview", headers=_auth(admin_user)
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client_optional, None)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dry_run"] == {
        "total_scanned": 1000,
        "total_matches": 42,
        "truncated": True,
    }
    # Capped limit + ~7-day window were passed through.
    assert captured["limit"] == 50
    window = captured["end_date"] - captured["start_date"]
    assert timedelta(days=6, hours=23) < window < timedelta(days=7, hours=1)
    assert captured["end_date"] <= datetime.now(UTC) + timedelta(minutes=1)
