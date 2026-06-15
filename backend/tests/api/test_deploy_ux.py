"""Tests for the Better Deployment UX backend (deploy-preview, deploy_progress
WS broadcast, rollback-and-redeploy).

These build on the dual-control feature already on main: the gate, the shared
``apply_sigma_rule_deployment`` path, and ``create_deployment_request``.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select

from app.api.deps import get_opensearch_client, get_opensearch_client_optional
from app.core.security import create_access_token, get_password_hash
from app.main import app
from app.models.deployment_request import DeploymentRequest
from app.models.index_pattern import IndexPattern
from app.models.notification_settings import NotificationSettings
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.setting import Setting
from app.models.user import User, UserRole

# A minimal but real Sigma rule that translates cleanly (one field: fieldA).
_VALID_YAML = (
    "title: {title}\nlogsource:\n  category: test\n"
    "detection:\n  selection:\n    fieldA: value\n  condition: selection\n"
)


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, role: UserRole, email: str) -> User:
    user = User(
        id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw"),
        role=role, is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _enable_gate(session) -> None:
    session.add(NotificationSettings(require_deploy_approval=True))
    await session.commit()


async def _seed_opensearch(session) -> None:
    session.add(
        Setting(key="opensearch", value={"host": "localhost", "port": 9200,
                                         "use_ssl": False, "verify_certs": False})
    )
    await session.commit()


async def _make_pull_pattern(session) -> IndexPattern:
    """A pull-mode pattern: no percolator interaction, current=null in preview."""
    ip = IndexPattern(
        id=uuid.uuid4(), name="pull-ux", pattern="pull-ux-*",
        percolator_index=".perc-pull-ux", mode="pull",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_push_pattern(session) -> IndexPattern:
    ip = IndexPattern(
        id=uuid.uuid4(), name="push-ux", pattern="push-ux-*",
        percolator_index=".perc-push-ux", mode="push",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_rule(session, ip, user, title="UX Rule", *, version=1,
                     status=RuleStatus.UNDEPLOYED, deployed_version=None):
    deployed_at = (
        __import__("datetime").datetime.now(__import__("datetime").UTC)
        if deployed_version is not None
        else None
    )
    rule = Rule(
        id=uuid.uuid4(), title=title, yaml_content=_VALID_YAML.format(title=title),
        severity="low", status=status, source=RuleSource.USER,
        index_pattern_id=ip.id, created_by=user.id, deployed_version=deployed_version,
        deployed_at=deployed_at,
    )
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=version,
                            yaml_content=_VALID_YAML.format(title=title),
                            changed_by=user.id, change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


async def _make_pending_request(session, rule, user):
    """File an OPEN (pending) DeploymentRequest with one item linked to ``rule``."""
    from app.models.deployment_request import (
        DeploymentRequestItem,
        DeploymentRequestKind,
        DeploymentRequestStatus,
    )

    req = DeploymentRequest(
        id=uuid.uuid4(), requested_by=user.id, change_reason="ship",
        status=DeploymentRequestStatus.PENDING.value,
    )
    req.items.append(
        DeploymentRequestItem(
            rule_id=rule.id, version_number=1,
            kind=DeploymentRequestKind.SIGMA.value,
        )
    )
    session.add(req)
    await session.commit()
    return req


# --------------------------------------------------------------------------- #
# D — has_open_request flag (Pending approval badge)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_has_open_request_flag_list_and_detail(
    client, test_session, admin_user
):
    """A rule with an OPEN pending DeploymentRequest reports has_open_request
    true in both the list and detail responses; another rule reports false."""
    ip = await _make_pull_pattern(test_session)
    pending_rule = await _make_rule(test_session, ip, admin_user, title="Pending One")
    clean_rule = await _make_rule(test_session, ip, admin_user, title="Clean One")
    await _make_pending_request(test_session, pending_rule, admin_user)

    # List
    resp = await client.get("/api/rules", headers=_auth(admin_user))
    assert resp.status_code == 200, resp.text
    by_id = {r["id"]: r for r in resp.json()}
    assert by_id[str(pending_rule.id)]["has_open_request"] is True
    assert by_id[str(clean_rule.id)]["has_open_request"] is False

    # Detail
    detail_pending = await client.get(
        f"/api/rules/{pending_rule.id}", headers=_auth(admin_user)
    )
    assert detail_pending.status_code == 200, detail_pending.text
    assert detail_pending.json()["has_open_request"] is True

    detail_clean = await client.get(
        f"/api/rules/{clean_rule.id}", headers=_auth(admin_user)
    )
    assert detail_clean.status_code == 200, detail_clean.text
    assert detail_clean.json()["has_open_request"] is False


@pytest.mark.asyncio
async def test_has_open_request_false_when_request_terminal(
    client, test_session, admin_user
):
    """A non-pending (e.g. applied) request must NOT set has_open_request."""
    from app.models.deployment_request import (
        DeploymentRequestItem,
        DeploymentRequestKind,
        DeploymentRequestStatus,
    )

    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user, title="Applied One")
    req = DeploymentRequest(
        id=uuid.uuid4(), requested_by=admin_user.id, change_reason="ship",
        status=DeploymentRequestStatus.APPLIED.value,
    )
    req.items.append(
        DeploymentRequestItem(
            rule_id=rule.id, version_number=1,
            kind=DeploymentRequestKind.SIGMA.value,
        )
    )
    test_session.add(req)
    await test_session.commit()

    resp = await client.get(f"/api/rules/{rule.id}", headers=_auth(admin_user))
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_open_request"] is False


# --------------------------------------------------------------------------- #
# A — deploy-preview
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_deploy_preview_deployed_pull_rule(
    client, test_session, admin_user, monkeypatch
):
    """A deployed pull-mode rule: proposed + validation + eligibility present,
    current=null (pull mode never touches the percolator)."""
    await _seed_opensearch(test_session)
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user, status=RuleStatus.DEPLOYED, deployed_version=1
    )

    resp = await client.get(
        f"/api/rules/{rule.id}/deploy-preview", headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["current_deployed_query"] is None  # pull mode: no percolator
    assert body["proposed_query"] is not None
    assert body["validation"]["success"] is True
    assert body["validation"]["errors"] == []
    assert body["eligibility"]["eligible"] is True
    assert body["deployed_version"] == 1
    assert body["current_version"] == 1
    assert body["needs_redeploy"] is False


@pytest.mark.asyncio
async def test_deploy_preview_deployed_push_rule_reads_percolator(
    client, test_session, admin_user, monkeypatch
):
    """Push-mode deployed rule returns the live percolator query as current."""
    await _seed_opensearch(test_session)
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )
    live_query = {"bool": {"must": [{"query_string": {"query": "fieldA:value"}}]}}
    monkeypatch.setattr(
        "app.services.percolator.PercolatorService.get_deployed_rule",
        lambda self, idx, rid: {"query": live_query},
    )
    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user, status=RuleStatus.DEPLOYED, deployed_version=1
    )

    # Mock OpenSearch client so push-mode preview resolves without a real cluster.
    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    app.dependency_overrides[get_opensearch_client_optional] = lambda: MagicMock()
    try:
        resp = await client.get(
            f"/api/rules/{rule.id}/deploy-preview", headers=_auth(admin_user)
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)
        app.dependency_overrides.pop(get_opensearch_client_optional, None)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["current_deployed_query"] == live_query
    assert body["proposed_query"] is not None


@pytest.mark.asyncio
async def test_deploy_preview_undeployed_rule_current_null(
    client, test_session, admin_user, monkeypatch
):
    """An undeployed rule has no live query -> current_deployed_query null."""
    await _seed_opensearch(test_session)
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user)  # UNDEPLOYED

    resp = await client.get(
        f"/api/rules/{rule.id}/deploy-preview", headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["current_deployed_query"] is None
    assert body["deployed_version"] is None
    assert body["proposed_query"] is not None
    assert body["validation"]["success"] is True


@pytest.mark.asyncio
async def test_deploy_preview_requires_deploy_permission(
    client, test_session, normal_user, admin_user
):
    """A viewer (no deploy_rules) gets 403."""
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user)

    resp = await client.get(
        f"/api/rules/{rule.id}/deploy-preview", headers=_auth(normal_user)
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_deploy_preview_rule_not_found(client, test_session, admin_user):
    resp = await client.get(
        f"/api/rules/{uuid.uuid4()}/deploy-preview", headers=_auth(admin_user)
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# C1 — deploy_progress WS broadcast (gate OFF direct path)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_bulk_deploy_emits_deploy_progress(
    client, test_session, admin_user, monkeypatch
):
    """Gate OFF bulk deploy broadcasts deploy_progress per rule transition."""
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)  # pull -> no real percolator write
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )
    r1 = await _make_rule(test_session, ip, admin_user, title="Bulk One")
    r2 = await _make_rule(test_session, ip, admin_user, title="Bulk Two")

    broadcasts: list[dict] = []

    async def _capture(message):
        broadcasts.append(message)

    monkeypatch.setattr(
        "app.services.websocket.manager.broadcast_to_all_local", _capture
    )

    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    try:
        resp = await client.post(
            "/api/rules/bulk/deploy",
            json={"rule_ids": [str(r1.id), str(r2.id)], "change_reason": "ship"},
            headers=_auth(admin_user),
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)

    assert resp.status_code == 200, resp.text

    progress = [m for m in broadcasts if m.get("type") == "deploy_progress"]
    # Two rules x {deploying, success} = at least 4 transitions.
    assert len(progress) >= 4
    statuses = {(m["rule_id"], m["status"]) for m in progress}
    assert (str(r1.id), "deploying") in statuses
    assert (str(r1.id), "success") in statuses
    assert (str(r2.id), "deploying") in statuses
    assert (str(r2.id), "success") in statuses
    # Every message carries the same batch_id and a rule_title.
    batch_ids = {m["batch_id"] for m in progress}
    assert len(batch_ids) == 1
    assert all(m.get("rule_title") for m in progress)


@pytest.mark.asyncio
async def test_bulk_deploy_broadcast_failure_does_not_break_deploy(
    client, test_session, admin_user, monkeypatch
):
    """A broadcast that raises must not fail the deploy (best-effort)."""
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)
    monkeypatch.setattr(
        "app.api.rules._shared.get_index_fields", lambda *a, **k: ["fieldA"]
    )
    rule = await _make_rule(test_session, ip, admin_user, title="Boom WS")

    async def _boom(message):
        raise RuntimeError("ws down")

    monkeypatch.setattr(
        "app.services.websocket.manager.broadcast_to_all_local", _boom
    )

    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    try:
        resp = await client.post(
            "/api/rules/bulk/deploy",
            json={"rule_ids": [str(rule.id)], "change_reason": "ship"},
            headers=_auth(admin_user),
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)

    assert resp.status_code == 200, resp.text
    assert str(rule.id) in resp.json()["success"]


# --------------------------------------------------------------------------- #
# E1 — rollback-and-redeploy
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_rollback_redeploy_gate_off_applies(
    client, test_session, admin_user, monkeypatch
):
    """Gate OFF: yaml rolls back to v1 (as new version) AND apply is called."""
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user, title="RR", version=1)

    # Land a second version with different content (the "live" current).
    test_session.add(RuleVersion(rule_id=rule.id, version_number=2,
                                 yaml_content=_VALID_YAML.format(title="RR v2"),
                                 changed_by=admin_user.id, change_reason="edit"))
    rule.yaml_content = _VALID_YAML.format(title="RR v2")
    await test_session.commit()

    from app.services.deployment import SigmaDeployResult

    apply_mock = AsyncMock(
        return_value=SigmaDeployResult(
            rule_id=rule.id, deployed_version=3,
            deployed_at=__import__("datetime").datetime.now(
                __import__("datetime").UTC),
        )
    )
    monkeypatch.setattr("app.api.rules._pending.apply_sigma_rule_deployment", apply_mock)

    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    try:
        resp = await client.post(
            f"/api/rules/{rule.id}/rollback-redeploy/1",
            json={"change_reason": "revert and ship"},
            headers=_auth(admin_user),
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)

    assert resp.status_code == 200, resp.text
    apply_mock.assert_awaited_once()

    # A new version (v3) was created carrying v1's content.
    versions = (await test_session.execute(
        select(RuleVersion).where(RuleVersion.rule_id == rule.id)
        .order_by(RuleVersion.version_number.desc())
    )).scalars().all()
    assert versions[0].version_number == 3
    assert versions[0].yaml_content == _VALID_YAML.format(title="RR")
    await test_session.refresh(rule)
    assert rule.yaml_content == _VALID_YAML.format(title="RR")


@pytest.mark.asyncio
async def test_rollback_redeploy_gate_on_files_request(
    client, test_session, admin_user, monkeypatch
):
    """Gate ON: rollback creates the version, then a DeploymentRequest is filed
    (202) instead of applying directly."""
    await _enable_gate(test_session)
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user, title="RRGate", version=1)
    test_session.add(RuleVersion(rule_id=rule.id, version_number=2,
                                 yaml_content=_VALID_YAML.format(title="RRGate v2"),
                                 changed_by=admin_user.id, change_reason="edit"))
    rule.yaml_content = _VALID_YAML.format(title="RRGate v2")
    await test_session.commit()

    apply_mock = AsyncMock()
    monkeypatch.setattr("app.api.rules._pending.apply_sigma_rule_deployment", apply_mock)

    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    try:
        resp = await client.post(
            f"/api/rules/{rule.id}/rollback-redeploy/1",
            json={"change_reason": "revert and ship"},
            headers=_auth(admin_user),
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)

    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "pending_approval"
    apply_mock.assert_not_called()

    # Rollback still happened (version created) but a request is pending.
    versions = (await test_session.execute(
        select(RuleVersion).where(RuleVersion.rule_id == rule.id)
        .order_by(RuleVersion.version_number.desc())
    )).scalars().all()
    assert versions[0].version_number == 3
    assert versions[0].yaml_content == _VALID_YAML.format(title="RRGate")

    reqs = (await test_session.execute(select(DeploymentRequest))).scalars().all()
    assert len(reqs) == 1


@pytest.mark.asyncio
async def test_rollback_redeploy_requires_deploy_permission(
    client, test_session, normal_user, admin_user
):
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user, version=1)
    resp = await client.post(
        f"/api/rules/{rule.id}/rollback-redeploy/1",
        json={"change_reason": "x"},
        headers=_auth(normal_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rollback_redeploy_unknown_version_404(
    client, test_session, admin_user
):
    await _seed_opensearch(test_session)
    ip = await _make_pull_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user, version=1)
    app.dependency_overrides[get_opensearch_client] = lambda: MagicMock()
    try:
        resp = await client.post(
            f"/api/rules/{rule.id}/rollback-redeploy/99",
            json={"change_reason": "x"},
            headers=_auth(admin_user),
        )
    finally:
        app.dependency_overrides.pop(get_opensearch_client, None)
    assert resp.status_code == 404
