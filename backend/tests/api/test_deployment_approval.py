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

    monkeypatch.setattr("app.api.rules.deploy.apply_sigma_rule_deployment", _fake_apply)

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
async def test_admin_can_self_approve(client, test_session, test_index_pattern, admin_user):
    # Admins are exempt from the self-review guard so a single-admin deployment
    # isn't permanently blocked (non-admin makers still need a separate checker).
    await _seed_opensearch(test_session)
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    rid = await _create_request(client, rule, admin_user)  # admin is the requester
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_admin_can_self_reject(client, test_session, test_index_pattern, admin_user):
    rule = await _make_rule(test_session, test_index_pattern, admin_user)
    rid = await _create_request(client, rule, admin_user)
    resp = await client.post(
        f"/api/deployment-requests/{rid}/reject",
        json={"review_note": "no"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text


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


@pytest.mark.asyncio
async def test_invalid_status_filter_422(client, test_session, admin_user):
    resp = await client.get(
        "/api/deployment-requests?status_filter=bogus", headers=_auth(admin_user)
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Integrity: approval deploys the PINNED (reviewed) version, not live content
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_apply_deploys_pinned_version(test_session, test_user, monkeypatch):
    """apply_sigma_rule_deployment uses pinned_yaml/version, not live content."""
    import uuid as _uuid

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.index_pattern import IndexPattern
    from app.services.deployment import apply_sigma_rule_deployment

    # Pull-mode pattern -> no percolator write (no real OpenSearch needed).
    ip = IndexPattern(id=_uuid.uuid4(), name="pull-p", pattern="pull-*",
                      percolator_index=".perc-pull", mode="pull")
    test_session.add(ip)
    await test_session.flush()

    pinned_yaml = (
        "title: Pinned\nlogsource:\n  category: test\n"
        "detection:\n  selection:\n    fieldA: value\n  condition: selection\n"
    )
    rule = Rule(id=_uuid.uuid4(), title="PinTest", yaml_content="title: LIVE v2 different",
                severity="low", status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
                index_pattern_id=ip.id, created_by=test_user.id)
    test_session.add(rule)
    await test_session.commit()
    res = await test_session.execute(
        select(Rule).where(Rule.id == rule.id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = res.scalar_one()

    # No unmapped fields (pull pattern has no index fields to check against here).
    monkeypatch.setattr("app.services.deployment.get_index_fields", lambda *a, **k: ["fieldA"])

    result = await apply_sigma_rule_deployment(
        test_session, object(), rule, actor_id=test_user.id, change_reason="x",
        pinned_yaml=pinned_yaml, pinned_version=1,
    )
    assert result.deployed_version == 1
    await test_session.refresh(rule)
    assert rule.deployed_version == 1
    assert rule.status == RuleStatus.DEPLOYED


# --------------------------------------------------------------------------- #
# No-bypass: field-mapping change must NOT silently redeploy when gate is ON
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_field_mapping_change_does_not_redeploy_when_gated(
    client, test_session, test_index_pattern, admin_user, monkeypatch
):
    import uuid as _uuid

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.field_mapping import FieldMapping, MappingOrigin

    await _enable_gate(test_session)
    await _seed_opensearch(test_session)

    mapping = FieldMapping(
        id=_uuid.uuid4(), index_pattern_id=test_index_pattern.id,
        sigma_field="process.name", target_field="process.name",
        origin=MappingOrigin.MANUAL, created_by=admin_user.id,
    )
    test_session.add(mapping)
    rule = await _make_rule(test_session, test_index_pattern, admin_user, title="Live")
    rule.status = RuleStatus.DEPLOYED
    rule.deployed_at = __import__("datetime").datetime.now(__import__("datetime").UTC)
    await test_session.commit()

    loaded_rule = (await test_session.execute(
        select(Rule).where(Rule.id == rule.id).options(selectinload(Rule.versions))
    )).scalar_one()

    redeploy_mock = AsyncMock(return_value={"status": "redeployed", "rule_id": str(rule.id)})
    monkeypatch.setattr(
        "app.services.rule_redeploy.redeploy_rule_to_percolator", redeploy_mock
    )

    async def _affected(_db, _mapping_id):
        return [loaded_rule]

    monkeypatch.setattr("app.services.field_mapping.get_rules_using_mapping", _affected)

    resp = await client.put(
        f"/api/field-mappings/{mapping.id}",
        json={"target_field": "process.name.keyword"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text
    # The bypass is closed: no silent percolator redeploy under dual-control.
    redeploy_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# Capstone E2E: real maker->checker batch flow through the real apply path
# (pull-mode so no OpenSearch needed; get_index_fields stubbed for introspection
#  only). No mock of the deploy service — exercises real translate/tracking/audit.
# --------------------------------------------------------------------------- #
_VALID_YAML = (
    "title: {title}\nlogsource:\n  category: test\n"
    "detection:\n  selection:\n    fieldA: value\n  condition: selection\n"
)


async def _make_pull_rule(session, ip, user, title):
    import uuid as _uuid

    rule = Rule(id=_uuid.uuid4(), title=title, yaml_content=_VALID_YAML.format(title=title),
                severity="low", status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
                index_pattern_id=ip.id, created_by=user.id)
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(rule_id=rule.id, version_number=1,
                            yaml_content=_VALID_YAML.format(title=title),
                            changed_by=user.id, change_reason="init"))
    await session.commit()
    await session.refresh(rule)
    return rule


@pytest.mark.asyncio
async def test_e2e_batch_maker_checker_flow(client, test_session, admin_user, monkeypatch):
    import uuid as _uuid

    from app.models.audit_log import AuditLog
    from app.models.index_pattern import IndexPattern

    await _enable_gate(test_session)
    await _seed_opensearch(test_session)
    monkeypatch.setattr("app.services.deployment.get_index_fields", lambda *a, **k: ["fieldA"])

    ip = IndexPattern(id=_uuid.uuid4(), name="e2e-pull", pattern="e2e-*",
                      percolator_index=".perc-e2e", mode="pull")
    test_session.add(ip)
    await test_session.flush()
    r1 = await _make_pull_rule(test_session, ip, admin_user, "E2E One")
    r2 = await _make_pull_rule(test_session, ip, admin_user, "E2E Two")

    maker = admin_user
    checker = await _make_user(test_session, UserRole.ADMIN, "checker-e2e@example.com")

    # 1. Maker deploys a batch via the gated bulk path -> 202 + one batch request.
    gate_resp = await client.post(
        "/api/rules/bulk/deploy",
        json={"rule_ids": [str(r1.id), str(r2.id)], "change_reason": "ship batch"},
        headers=_auth(maker),
    )
    assert gate_resp.status_code == 202, gate_resp.text
    rid = gate_resp.json()["deployment_request_id"]

    # 2. A separate checker approves -> REAL apply (no mock) -> APPLIED, both DEPLOYED.
    appr = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(checker)
    )
    assert appr.status_code == 200, appr.text
    body = appr.json()
    assert body["status"] == DeploymentRequestStatus.APPLIED.value
    assert {i["apply_status"] for i in body["items"]} == {"ok"}
    assert body["reviewed_by"] == str(checker.id)

    # Fresh column-select reflects the real apply (bypasses the stale identity map).
    rows = (await test_session.execute(
        select(Rule.status, Rule.deployed_version).where(Rule.id.in_([r1.id, r2.id]))
    )).all()
    assert len(rows) == 2
    assert all(s == RuleStatus.DEPLOYED and dv == 1 for s, dv in rows)

    # 4. Audit shows the maker filed and the checker approved/applied.
    actions = (await test_session.execute(select(AuditLog.action, AuditLog.user_id))).all()
    by_action = {a: u for a, u in actions}
    assert by_action.get("deployment_request.created") == maker.id
    assert by_action.get("deployment_request.approved") == checker.id
    assert by_action.get("deployment_request.applied") == checker.id

    # 5. A second request can be rejected with a reason.
    rid2 = await _create_request(client, r1, maker)
    rej = await client.post(
        f"/api/deployment-requests/{rid2}/reject",
        json={"review_note": "not now"},
        headers=_auth(checker),
    )
    assert rej.status_code == 200
    assert rej.json()["status"] == DeploymentRequestStatus.REJECTED.value
    assert rej.json()["review_note"] == "not now"
