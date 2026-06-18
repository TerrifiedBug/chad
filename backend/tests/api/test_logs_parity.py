"""Parity tests: sync receive_logs must match async LogProcessor for
threshold gating and group_id-aware exception suppression."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import logs as logs_module
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleStatus
from app.models.rule_exception import ExceptionOperator, RuleException
from app.models.user import User


def _make_request() -> MagicMock:
    """Minimal FastAPI Request stand-in (only client IP is read, and only
    when an allowlist is configured — which these patterns do not set)."""
    req = MagicMock()
    req.client.host = "127.0.0.1"
    req.headers = {}
    return req


@pytest_asyncio.fixture
async def index_pattern(test_session: AsyncSession) -> IndexPattern:
    pattern = IndexPattern(
        id=uuid.uuid4(),
        name="parity-test",
        pattern="parity-*",
        percolator_index="chad-percolator-parity",
    )
    test_session.add(pattern)
    await test_session.commit()
    await test_session.refresh(pattern)
    return pattern


@pytest_asyncio.fixture
async def base_rule(
    test_session: AsyncSession, index_pattern: IndexPattern, test_user: User
) -> Rule:
    rule = Rule(
        id=uuid.uuid4(),
        title="Parity Rule",
        description="rule for parity tests",
        yaml_content="title: t\ndetection:\n  selection:\n    x: 1\n  condition: selection",
        severity="high",
        status=RuleStatus.DEPLOYED,
        index_pattern_id=index_pattern.id,
        created_by=test_user.id,
    )
    test_session.add(rule)
    await test_session.commit()
    await test_session.refresh(rule)
    return rule


def _patch_ingest_io(monkeypatch_targets: dict):
    """Patch the OpenSearch-facing collaborators of receive_logs so the path
    runs without a live cluster. Returns the patch context managers list."""
    return monkeypatch_targets


class TestExceptionGroupParity:
    @pytest.mark.asyncio
    async def test_and_group_suppresses_via_sync_path(
        self, test_session: AsyncSession, index_pattern, base_rule, test_user
    ):
        """Two exceptions sharing one group_id are ANDed: when BOTH conditions
        match, the sync path must suppress the alert (no alert created)."""
        group = uuid.uuid4()
        test_session.add_all([
            RuleException(
                id=uuid.uuid4(), rule_id=base_rule.id, group_id=group,
                field="user", operator=ExceptionOperator.EQUALS, value="admin",
                is_active=True, created_by=test_user.id,
            ),
            RuleException(
                id=uuid.uuid4(), rule_id=base_rule.id, group_id=group,
                field="host", operator=ExceptionOperator.EQUALS, value="prod-01",
                is_active=True, created_by=test_user.id,
            ),
        ])
        await test_session.commit()

        log = {"@timestamp": "2026-06-18T00:00:00Z", "user": "admin", "host": "prod-01"}
        match = {
            "rule_id": str(base_rule.id), "rule_title": "Parity Rule",
            "severity": "high", "tags": [], "enabled": True,
        }

        os_client = MagicMock()
        os_client.indices.exists.return_value = True
        alert_service = MagicMock()
        alert_service.bulk_create_alerts.return_value = []

        with patch.object(logs_module, "batch_percolate_logs", return_value={0: [match]}), \
             patch.object(logs_module, "AlertService", return_value=alert_service), \
             patch.object(logs_module, "enrich_alert", new=AsyncMock(side_effect=lambda db, doc, ip, **k: doc)), \
             patch.object(logs_module.manager, "broadcast_alert", new=AsyncMock()), \
             patch.object(logs_module, "check_correlation", new=AsyncMock(return_value=[])):
            resp = await logs_module.receive_logs(
                index_suffix="parity",
                logs=[log],
                request=_make_request(),
                background_tasks=BackgroundTasks(),
                db=test_session,
                authorization=f"Bearer {index_pattern.auth_token}",
                os_client=os_client,
            )

        assert resp.matches_found == 0
        alert_service.bulk_create_alerts.assert_not_called()

    @pytest.mark.asyncio
    async def test_separate_groups_or_not_collapsed_to_and(
        self, test_session: AsyncSession, index_pattern, base_rule, test_user
    ):
        """Two exceptions in DIFFERENT groups are ORed. A log matching exactly
        one group's sole condition must be suppressed. Without group_id both
        rows collapse into one AND-group and the alert wrongly fires."""
        test_session.add_all([
            RuleException(
                id=uuid.uuid4(), rule_id=base_rule.id, group_id=uuid.uuid4(),
                field="user", operator=ExceptionOperator.EQUALS, value="admin",
                is_active=True, created_by=test_user.id,
            ),
            RuleException(
                id=uuid.uuid4(), rule_id=base_rule.id, group_id=uuid.uuid4(),
                field="host", operator=ExceptionOperator.EQUALS, value="prod-01",
                is_active=True, created_by=test_user.id,
            ),
        ])
        await test_session.commit()

        # Matches ONLY the first group's condition (user=admin); host differs.
        log = {"@timestamp": "2026-06-18T00:00:00Z", "user": "admin", "host": "other"}
        match = {
            "rule_id": str(base_rule.id), "rule_title": "Parity Rule",
            "severity": "high", "tags": [], "enabled": True,
        }

        os_client = MagicMock()
        os_client.indices.exists.return_value = True
        alert_service = MagicMock()
        alert_service.bulk_create_alerts.return_value = []

        with patch.object(logs_module, "batch_percolate_logs", return_value={0: [match]}), \
             patch.object(logs_module, "AlertService", return_value=alert_service), \
             patch.object(logs_module, "enrich_alert", new=AsyncMock(side_effect=lambda db, doc, ip, **k: doc)), \
             patch.object(logs_module.manager, "broadcast_alert", new=AsyncMock()), \
             patch.object(logs_module, "check_correlation", new=AsyncMock(return_value=[])):
            resp = await logs_module.receive_logs(
                index_suffix="parity",
                logs=[log],
                request=_make_request(),
                background_tasks=BackgroundTasks(),
                db=test_session,
                authorization=f"Bearer {index_pattern.auth_token}",
                os_client=os_client,
            )

        # First OR-group fully matches (user=admin) → suppress, no alert.
        assert resp.matches_found == 0
        alert_service.bulk_create_alerts.assert_not_called()


class TestThresholdParity:
    @pytest.mark.asyncio
    async def test_threshold_rule_does_not_fire_below_n_then_fires_at_n(
        self, test_session: AsyncSession, index_pattern, test_user
    ):
        """A count rule (threshold_count=3) must NOT create an alert on the
        first two matches and MUST create one on the third — via the sync path."""
        rule = Rule(
            id=uuid.uuid4(),
            title="Sync Threshold Rule",
            description="count rule",
            yaml_content="title: t\ndetection:\n  selection:\n    x: 1\n  condition: selection",
            severity="high",
            status=RuleStatus.DEPLOYED,
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
            threshold_enabled=True,
            threshold_count=3,
            threshold_window_minutes=10,
            threshold_group_by=None,
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        match = {
            "rule_id": str(rule.id), "rule_title": "Sync Threshold Rule",
            "severity": "high", "tags": [], "enabled": True,
        }
        alert_service = MagicMock()
        alert_service.bulk_create_alerts.return_value = []
        os_client = MagicMock()
        os_client.indices.exists.return_value = True

        async def _send(i: int):
            # Distinct content per call so deterministic ids differ and each is
            # a separate threshold match row.
            log = {"@timestamp": "2026-06-18T00:00:00Z", "x": 1, "seq": i}
            with patch.object(logs_module, "batch_percolate_logs", return_value={0: [match]}), \
                 patch.object(logs_module, "AlertService", return_value=alert_service), \
                 patch.object(logs_module, "enrich_alert", new=AsyncMock(side_effect=lambda db, doc, ip, **k: doc)), \
                 patch.object(logs_module.manager, "broadcast_alert", new=AsyncMock()), \
                 patch.object(logs_module, "check_correlation", new=AsyncMock(return_value=[])):
                return await logs_module.receive_logs(
                    index_suffix="parity",
                    logs=[log],
                    request=_make_request(),
                    background_tasks=BackgroundTasks(),
                    db=test_session,
                    authorization=f"Bearer {index_pattern.auth_token}",
                    os_client=os_client,
                )

        r1 = await _send(1)
        r2 = await _send(2)
        r3 = await _send(3)

        assert r1.matches_found == 0
        assert r2.matches_found == 0
        assert r3.matches_found == 1
        # Only the threshold-meeting batch should bulk-write.
        assert alert_service.bulk_create_alerts.call_count == 1
