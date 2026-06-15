"""Tests for the deployment-request lifecycle API (create/list/detail/cancel/stats)."""

import uuid

import pytest
from sqlalchemy import select

from app.core.security import create_access_token
from app.models.audit_log import AuditLog
from app.models.deployment_request import DeploymentRequestStatus
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, role: UserRole, email: str) -> User:
    from app.core.security import get_password_hash

    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=get_password_hash("pw"),
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


# --------------------------------------------------------------------------- #
# create
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_create_request_happy(client, test_session, test_rule, admin_user):
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "ship it"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == DeploymentRequestStatus.PENDING.value
    assert body["item_count"] == 1
    assert body["requested_by"] == str(admin_user.id)
    assert body["rule_titles"] == [test_rule.title]

    # Audit row emitted.
    rows = await test_session.execute(
        select(AuditLog).where(AuditLog.action == "deployment_request.created")
    )
    assert rows.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_create_request_empty_rejected(client, admin_user):
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_request_missing_rule_404(client, admin_user):
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(uuid.uuid4())], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_viewer_cannot_create(client, test_session, test_rule, normal_user):
    """normal_user is a VIEWER -> lacks deploy_rules."""
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(normal_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_create(client, test_session, test_rule):
    analyst = await _make_user(test_session, UserRole.ANALYST, "analyst-create@example.com")
    resp = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(analyst),
    )
    assert resp.status_code == 201


# --------------------------------------------------------------------------- #
# list / detail / stats
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_list_and_status_filter(client, test_session, test_rule, admin_user):
    await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    resp = await client.get("/api/deployment-requests", headers=_auth(admin_user))
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_pending = await client.get(
        "/api/deployment-requests?status_filter=pending", headers=_auth(admin_user)
    )
    assert len(resp_pending.json()) == 1
    resp_applied = await client.get(
        "/api/deployment-requests?status_filter=applied", headers=_auth(admin_user)
    )
    assert resp_applied.json() == []


@pytest.mark.asyncio
async def test_detail_includes_proposed_yaml(client, test_session, test_rule, admin_user):
    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    rid = create.json()["id"]
    resp = await client.get(f"/api/deployment-requests/{rid}", headers=_auth(admin_user))
    assert resp.status_code == 200
    detail = resp.json()
    assert len(detail["items"]) == 1
    item = detail["items"][0]
    assert item["proposed_yaml"] == test_rule.yaml_content
    assert item["is_stale"] is False


@pytest.mark.asyncio
async def test_detail_marks_stale_after_edit(
    client, test_session, test_index_pattern, admin_user
):
    """A pinned request goes stale when the rule gains a newer version."""
    rule = Rule(
        id=uuid.uuid4(),
        title="Staleable",
        yaml_content="title: v1",
        severity="low",
        status=RuleStatus.UNDEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=test_index_pattern.id,
        created_by=admin_user.id,
    )
    test_session.add(rule)
    await test_session.flush()
    test_session.add(
        RuleVersion(rule_id=rule.id, version_number=1, yaml_content="title: v1",
                    changed_by=admin_user.id, change_reason="init")
    )
    await test_session.commit()

    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    rid = create.json()["id"]

    # A new version lands after the request was filed.
    test_session.add(
        RuleVersion(rule_id=rule.id, version_number=2, yaml_content="title: v2",
                    changed_by=admin_user.id, change_reason="edit")
    )
    await test_session.commit()
    # Tests share one session across write+read; a real request uses a fresh
    # session that always reloads. Expire just the rule so the detail query
    # reloads its versions (and sees v2) without disturbing other objects.
    test_session.expire(rule)

    resp = await client.get(f"/api/deployment-requests/{rid}", headers=_auth(admin_user))
    item = resp.json()["items"][0]
    assert item["version_number"] == 1
    assert item["is_stale"] is True
    assert item["proposed_yaml"] == "title: v1"


@pytest.mark.asyncio
async def test_stats(client, test_session, test_rule, admin_user):
    await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    resp = await client.get("/api/deployment-requests/stats", headers=_auth(admin_user))
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["pending"] == 1
    assert stats["applied"] == 0


# --------------------------------------------------------------------------- #
# cancel
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_cancel_by_requester(client, test_session, test_rule, admin_user):
    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    rid = create.json()["id"]
    resp = await client.post(
        f"/api/deployment-requests/{rid}/cancel", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == DeploymentRequestStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_cancel_by_non_requester_forbidden(client, test_session, test_rule, admin_user):
    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    rid = create.json()["id"]
    other_admin = await _make_user(test_session, UserRole.ADMIN, "other-admin@example.com")
    resp = await client.post(
        f"/api/deployment-requests/{rid}/cancel", json={}, headers=_auth(other_admin)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_cancel_non_pending_conflict(client, test_session, test_rule, admin_user):
    create = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(test_rule.id)], "change_reason": "x"},
        headers=_auth(admin_user),
    )
    rid = create.json()["id"]
    await client.post(f"/api/deployment-requests/{rid}/cancel", json={}, headers=_auth(admin_user))
    # Second cancel -> already cancelled -> 409.
    resp = await client.post(
        f"/api/deployment-requests/{rid}/cancel", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 409
