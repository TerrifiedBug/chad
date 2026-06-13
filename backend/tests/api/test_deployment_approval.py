"""Tests for dual-control approve/reject + the gate on every deploy path.

Covers the security-critical guarantees: no-bypass gating, self-review guard,
permission matrix, atomic claim (lost race), stale block, batch partial failure.
The real percolator apply is patched out here (covered by the service tests +
the manual E2E); these tests exercise the lifecycle/authorisation logic.
"""

import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.security import create_access_token, get_password_hash
from app.models.deployment_request import DeploymentRequest, DeploymentRequestStatus
from app.models.notification_settings import NotificationSettings
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.services.deployment import DeploymentApplyError


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
    """A dummy OpenSearch setting so get_opensearch_client resolves (lazy, no connection)."""
    session.add(
        Setting(key="opensearch", value={"host": "localhost", "port": 9200,
                                          "use_ssl": False, "verify_certs": False})
    )
    await session.commit()


async def _make_rule(session, index_pattern, user, title="Gated Rule", version=1):
    rule = Rule(
        id=uuid.uuid4(), title=title, yaml_content=f"title: {title}", severity="low",
        status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
        index_pattern_id=index_pattern.id, created_by=user.id,
    )
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=version,
                            yaml_content=f"title: {title}", changed_by=user.id,
                            change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


# --------------------------------------------------------------------------- #
# No-bypass: the gate fires on every percolator-write path (202 + request)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_gate_fires_on_deploy(client, test_session, test_index_pattern, admin_user):
    await _enable_gate(test_session)
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)

    resp = await client.post(
        f"/api/rules/{rule.id}/deploy",
        json={"change_reason": "ship"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "pending_approval"
    # Rule must NOT have been deployed.
    await test_session.refresh(rule)
    assert rule.status == RuleStatus.UNDEPLOYED
    reqs = (await test_session.execute(select(DeploymentRequest))).scalars().all()
    assert len(reqs) == 1


@pytest.mark.asyncio
async def test_gate_fires_on_bulk_deploy(client, test_session, test_index_pattern, admin_user):
    await _enable_gate(test_session)
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)

    resp = await client.post(
        "/api/rules/bulk/deploy",
        json={"rule_ids": [str(rule.id)], "change_reason": "ship"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 202, resp.text
    reqs = (await test_session.execute(select(DeploymentRequest))).scalars().all()
    assert len(reqs) == 1


@pytest.mark.asyncio
async def test_gate_fires_on_unsnooze(client, test_session, test_index_pattern, admin_user):
    await _enable_gate(test_session)
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    rule.status = RuleStatus.SNOOZED
    rule.snooze_indefinite = True
    await test_session.commit()

    resp = await client.post(
        f"/api/rules/{rule.id}/unsnooze",
        json={"change_reason": "reactivate"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 202, resp.text
    await test_session.refresh(rule)
    assert rule.status == RuleStatus.SNOOZED  # not actually unsnoozed yet


@pytest.mark.asyncio
async def test_gate_fires_on_correlation_deploy(client, test_session, correlation_rule, admin_user):
    await _enable_gate(test_session)

    resp = await client.post(
        f"/api/correlation-rules/{correlation_rule.id}/deploy",
        json={"change_reason": "ship corr"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 202, resp.text
    await test_session.refresh(correlation_rule)
    assert correlation_rule.deployed_at is None  # not activated


@pytest.mark.asyncio
async def test_gate_off_deploy_goes_direct(
    client, test_session, test_index_pattern, admin_user, monkeypatch
):
    """Gate OFF -> direct deploy path (no DeploymentRequest created)."""
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)

    from app.services.deployment import SigmaDeployResult

    async def _fake_apply(db, os_client, r, **kw):
        return SigmaDeployResult(rule_id=r.id, deployed_version=1,
                                 deployed_at=__import__("datetime").datetime.now(
                                     __import__("datetime").UTC))

    monkeypatch.setattr("app.api.rules.apply_sigma_rule_deployment", _fake_apply)

    resp = await client.post(
        f"/api/rules/{rule.id}/deploy",
        json={"change_reason": "ship"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text
    reqs = (await test_session.execute(select(DeploymentRequest))).scalars().all()
    assert reqs == []


# --------------------------------------------------------------------------- #
# approve / reject lifecycle
# --------------------------------------------------------------------------- #
async def _create_request(client, rule, user) -> str:
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(rule.id)], "change_reason": "x"},
        headers=_auth(user),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_approve_happy(client, test_session, test_index_pattern, admin_user, monkeypatch):
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker@example.com")
    rid = await _create_request(client, rule, requester)

    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", AsyncMock(return_value=None)
    )
    # admin_user is a different person -> valid checker.
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == DeploymentRequestStatus.APPLIED.value
    assert body["items"][0]["apply_status"] == "ok"
    assert body["reviewed_by"] == str(admin_user.id)


@pytest.mark.asyncio
async def test_self_review_guard_approve(client, test_session, test_index_pattern, admin_user):
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    rid = await _create_request(client, rule, admin_user)  # admin is the requester
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_self_review_guard_reject(client, test_session, test_index_pattern, admin_user):
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    rid = await _create_request(client, rule, admin_user)
    resp = await client.post(
        f"/api/deployment-requests/{rid}/reject",
        json={"review_note": "no"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_cannot_approve(client, test_session, test_index_pattern, admin_user):
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker2@example.com")
    rid = await _create_request(client, rule, requester)
    analyst_checker = await _make_user(test_session, UserRole.ANALYST, "checker@example.com")
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(analyst_checker)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_atomic_claim_lost_race(
    client, test_session, test_index_pattern, admin_user, monkeypatch
):
    """Second approval after the request is already applied -> 409."""
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker3@example.com")
    rid = await _create_request(client, rule, requester)
    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", AsyncMock(return_value=None)
    )
    first = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert first.status_code == 200
    second = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_stale_blocks_approval(client, test_session, test_index_pattern, admin_user):
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user, version=1)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker4@example.com")
    rid = await _create_request(client, rule, requester)

    # A new version lands after the request -> request is stale.
    test_session.add(RuleVersion(rule_id=rule.id, version_number=2, yaml_content="title: v2",
                                 changed_by=admin_user.id, change_reason="edit"))
    await test_session.commit()
    test_session.expire(rule)

    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 409
    req = (await test_session.execute(
        select(DeploymentRequest).where(DeploymentRequest.id == uuid.UUID(rid))
    )).scalar_one()
    assert req.status == DeploymentRequestStatus.STALE.value


@pytest.mark.asyncio
async def test_batch_partial_failure(
    client, test_session, test_index_pattern, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)
    good = await _make_rule(test_session, test_index_pattern, admin_user, title="Good")
    bad = await _make_rule(test_session, test_index_pattern, admin_user, title="Bad")
    requester = await _make_user(test_session, UserRole.ANALYST, "maker5@example.com")

    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(good.id), str(bad.id)], "change_reason": "x"},
        headers=_auth(requester),
    )
    rid = create.json()["id"]

    async def _apply_side_effect(db, os_client, r, **kw):
        if r.id == bad.id:
            raise DeploymentApplyError("boom", kind="translation")
        return None

    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", _apply_side_effect
    )
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == DeploymentRequestStatus.FAILED.value
    statuses = {i["rule_id"]: i["apply_status"] for i in body["items"]}
    assert statuses[str(good.id)] == "ok"
    assert statuses[str(bad.id)] == "failed"


@pytest.mark.asyncio
async def test_reject_with_note(client, test_session, test_index_pattern, admin_user):
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker6@example.com")
    rid = await _create_request(client, rule, requester)
    resp = await client.post(
        f"/api/deployment-requests/{rid}/reject",
        json={"review_note": "needs work"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == DeploymentRequestStatus.REJECTED.value
    assert resp.json()["review_note"] == "needs work"


@pytest.mark.asyncio
async def test_reject_requires_note(client, test_session, test_index_pattern, admin_user):
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker7@example.com")
    rid = await _create_request(client, rule, requester)
    resp = await client.post(
        f"/api/deployment-requests/{rid}/reject", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 422
