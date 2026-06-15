"""Tests for maker-checker hardening (I3): quorum, resubmit, approval SLA."""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.core.security import create_access_token, get_password_hash
from app.models.notification_settings import NotificationSettings
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.setting import Setting
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, role: UserRole, email: str) -> User:
    user = User(id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw"),
                role=role, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _seed(session) -> None:
    session.add(NotificationSettings(require_deploy_approval=True))
    session.add(Setting(key="opensearch", value={"host": "localhost", "port": 9200,
                                                  "use_ssl": False, "verify_certs": False}))
    await session.commit()


async def _make_rule(session, index_pattern, user, title="Gated Rule"):
    rule = Rule(id=uuid.uuid4(), title=title, yaml_content=f"title: {title}", severity="low",
                status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
                index_pattern_id=index_pattern.id, created_by=user.id)
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=1, yaml_content=f"title: {title}",
                            changed_by=user.id, change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


async def _file(client, rule, user, required_approvals=None):
    body = {"rule_ids": [str(rule.id)], "change_reason": "x"}
    if required_approvals is not None:
        body["required_approvals"] = required_approvals
    resp = await client.post("/api/deployment-requests", json=body, headers=_auth(user))
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_quorum_requires_two_approvers(client, test_session, test_index_pattern, admin_user, monkeypatch):
    await _seed(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker@example.com")
    checker2 = await _make_user(test_session, UserRole.ADMIN, "checker2@example.com")

    created = await _file(client, rule, requester, required_approvals=2)
    assert created["required_approvals"] == 2
    rid = created["id"]

    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", AsyncMock(return_value=None)
    )

    # First approval: stays pending (1 of 2).
    r1 = await client.post(f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user))
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "pending"
    assert r1.json()["approvals_count"] == 1

    # Same approver cannot approve again.
    dup = await client.post(f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user))
    assert dup.status_code == 409

    # Second distinct approver meets quorum → applies.
    r2 = await client.post(f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(checker2))
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "applied"
    assert r2.json()["approvals_count"] == 2


@pytest.mark.asyncio
async def test_single_approval_still_default(client, test_session, test_index_pattern, admin_user, monkeypatch):
    await _seed(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker2@example.com")
    created = await _file(client, rule, requester)  # default required_approvals=1
    assert created["required_approvals"] == 1

    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", AsyncMock(return_value=None)
    )
    resp = await client.post(f"/api/deployment-requests/{created['id']}/approve", json={}, headers=_auth(admin_user))
    assert resp.json()["status"] == "applied"


@pytest.mark.asyncio
async def test_resubmit_after_rejection(client, test_session, test_index_pattern, admin_user):
    await _seed(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker3@example.com")
    created = await _file(client, rule, requester)
    rid = created["id"]

    # Reject it.
    rej = await client.post(f"/api/deployment-requests/{rid}/reject",
                            json={"review_note": "no"}, headers=_auth(admin_user))
    assert rej.status_code == 200
    assert rej.json()["status"] == "rejected"

    # Resubmit creates a fresh PENDING request.
    re = await client.post(f"/api/deployment-requests/{rid}/resubmit", json={}, headers=_auth(requester))
    assert re.status_code == 201, re.text
    assert re.json()["status"] == "pending"
    assert re.json()["id"] != rid


@pytest.mark.asyncio
async def test_list_loads_approvals_without_500(client, test_session, test_index_pattern, admin_user):
    # Regression: the list endpoint must eager-load `approvals`; _build_summary
    # reads len(req.approvals) and otherwise lazy-loads in async → 500.
    await _seed(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker5@example.com")
    created = await _file(client, rule, requester, required_approvals=2)
    # Record one approval (stays pending with 1/2).
    await client.post(f"/api/deployment-requests/{created['id']}/approve", json={}, headers=_auth(admin_user))

    listed = await client.get("/api/deployment-requests?status_filter=pending", headers=_auth(admin_user))
    assert listed.status_code == 200, listed.text
    row = next(r for r in listed.json() if r["id"] == created["id"])
    assert row["approvals_count"] == 1
    assert row["required_approvals"] == 2


@pytest.mark.asyncio
async def test_cannot_resubmit_pending(client, test_session, test_index_pattern, admin_user):
    await _seed(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    requester = await _make_user(test_session, UserRole.ANALYST, "maker4@example.com")
    created = await _file(client, rule, requester)
    re = await client.post(f"/api/deployment-requests/{created['id']}/resubmit", json={}, headers=_auth(requester))
    assert re.status_code == 409
