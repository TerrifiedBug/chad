"""Tests for rule Promotions + per-env dual-control (Model B).

Promotion = advance the TARGET env's pinned version to the version currently
deployed in the SOURCE env. The rule definition is never copied: we deploy the
source env's pinned version into the target env's percolator namespace + binding.

Covers:
- promote deploys the SOURCE env's pinned version into the target binding +
  namespace (not the rule's drifted live content);
- preflight reports a rule not-deployed-in-source as ineligible;
- target ``require_deploy_approval`` on -> promote files a DeploymentRequest
  tagged with target_environment_id (pending / 202-style);
- approving that request applies INTO the target env (target binding updated,
  the default env untouched);
- stale check on promote-approve;
- regression: an existing dual-control request (target_environment_id null)
  still applies into the default env.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.security import create_access_token, get_password_hash
from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestStatus,
)
from app.models.environment import Environment, RuleEnvironmentDeployment
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.setting import Setting
from app.models.user import User, UserRole

# A valid sigma rule body parameterised by a detection value so the source and
# live versions can drift and the deployed (translated) query proves which one
# was used.
_YAML = (
    "title: {title}\nlogsource:\n  category: test\n"
    "detection:\n  selection:\n    fieldA: {value}\n  condition: selection\n"
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


async def _seed_opensearch(session) -> None:
    """Dummy OpenSearch setting so get_opensearch_client resolves (lazy)."""
    session.add(
        Setting(key="opensearch", value={"host": "localhost", "port": 9200,
                                         "use_ssl": False, "verify_certs": False})
    )
    await session.commit()


async def _make_push_pattern(session, name="promo-push") -> IndexPattern:
    ip = IndexPattern(
        id=uuid.uuid4(), name=name, pattern=f"{name}-*",
        percolator_index=f".perc-{name}", mode="push",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_env(session, name, *, is_default=False, team_id=None,
                    require_deploy_approval=False) -> Environment:
    env = Environment(
        id=uuid.uuid4(), name=name, is_default=is_default, team_id=team_id,
        require_deploy_approval=require_deploy_approval,
    )
    session.add(env)
    await session.commit()
    await session.refresh(env)
    return env


async def _make_rule(session, ip, user, title="Promo Rule", *, live_value="live",
                     versions: dict[int, str] | None = None) -> Rule:
    """Create a rule. ``versions`` maps version_number -> detection value.

    The rule's live ``yaml_content`` uses ``live_value`` so it can drift from a
    pinned version. ``Rule.deployed_version`` is left null (per-env bindings hold
    the deployment state for promotions).
    """
    rule = Rule(
        id=uuid.uuid4(), title=title,
        yaml_content=_YAML.format(title=title, value=live_value),
        severity="low", status=RuleStatus.UNDEPLOYED, source=RuleSource.USER,
        index_pattern_id=ip.id, created_by=user.id,
    )
    session.add(rule)
    await session.flush()
    for vnum, value in (versions or {1: live_value}).items():
        session.add(RuleVersion(
            rule_id=rule.id, version_number=vnum,
            yaml_content=_YAML.format(title=title, value=value),
            changed_by=user.id, change_reason=f"v{vnum}",
        ))
    await session.commit()
    await session.refresh(rule)
    return rule


async def _bind(session, rule, env, *, version, status=RuleStatus.DEPLOYED.value):
    binding = RuleEnvironmentDeployment(
        rule_id=rule.id, environment_id=env.id, deployed_version=version,
        deployed_at=datetime.now(UTC), status=status,
    )
    session.add(binding)
    await session.commit()
    await session.refresh(binding)
    return binding


def _patch_percolator(monkeypatch) -> dict:
    """Patch out OpenSearch field introspection + percolator writes; capture the
    deployed percolator index name and translated query."""
    captured: dict = {}
    monkeypatch.setattr(
        "app.services.deployment.get_index_fields", lambda *a, **k: ["fieldA"]
    )

    def _fake_deploy(self, *, percolator_index, rule_id, query, title, severity, tags):
        captured["percolator_index"] = percolator_index
        captured["query"] = query
        captured["title"] = title

    monkeypatch.setattr(
        "app.services.percolator.PercolatorService.deploy_rule", _fake_deploy
    )
    monkeypatch.setattr(
        "app.services.percolator.PercolatorService.ensure_percolator_index",
        lambda self, *a, **k: None,
    )
    return captured


# --------------------------------------------------------------------------- #
# A. Promote deploys the SOURCE env's pinned version into the target
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_promote_deploys_source_pinned_version_into_target(
    client, test_session, admin_user, monkeypatch
):
    """Dev(v1)->Prod: the target binding + percolator namespace get the SOURCE
    env's pinned version, and the deployed query reflects the pinned (not the
    drifted live) content."""
    await _seed_opensearch(test_session)
    captured = _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    # Live content drifted to v2 ('drifted'); the source (Dev) is pinned at v1.
    rule = await _make_rule(
        test_session, ip, admin_user, live_value="drifted",
        versions={1: "pinnedsource", 2: "drifted"},
    )
    dev = await _make_env(test_session, "Dev")
    prod = await _make_env(test_session, "Prod")
    # Deployed in Dev at v1 (the version to promote).
    await _bind(test_session, rule, dev, version=1)

    resp = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "promote dev->prod",
        },
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deployment_request_id"] is None
    result = body["results"][0]
    assert result["rule_id"] == str(rule.id)
    assert result["status"] == "promoted"
    assert result["source_version"] == 1

    # Wrote into Prod's prefixed percolator namespace (target), not Dev's.
    assert captured["percolator_index"] == "chad-percolator-prod-promo-push"
    # The deployed query is the PINNED source content ('pinnedsource'),
    # never the drifted live content ('drifted').
    assert "pinnedsource" in str(captured["query"])
    assert "drifted" not in str(captured["query"])

    # Target binding upserted at the source's pinned version.
    prod_binding = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.rule_id == rule.id,
                RuleEnvironmentDeployment.environment_id == prod.id,
            )
        )
    ).scalar_one()
    assert prod_binding.deployed_version == 1
    assert prod_binding.status == RuleStatus.DEPLOYED.value

    # Non-default target env: the scalar Rule.deployed_* stay untouched.
    await test_session.refresh(rule)
    assert rule.deployed_at is None
    assert rule.status == RuleStatus.UNDEPLOYED


# --------------------------------------------------------------------------- #
# A2. Preflight: a rule not deployed in the source env is ineligible
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_preflight_rule_not_deployed_in_source_is_ineligible(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)
    captured = _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(test_session, ip, admin_user)
    dev = await _make_env(test_session, "Dev")
    prod = await _make_env(test_session, "Prod")
    # No Dev binding -> not deployed in source.

    resp = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "x",
        },
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()["results"][0]
    assert result["status"] == "ineligible"
    assert "not deployed in the source" in result["reason"].lower()

    # Nothing was promoted: no target binding, no percolator write.
    assert "percolator_index" not in captured
    bindings = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.environment_id == prod.id
            )
        )
    ).scalars().all()
    assert bindings == []


@pytest.mark.asyncio
async def test_preflight_mixed_eligible_and_ineligible(
    client, test_session, admin_user, monkeypatch
):
    """A mix promotes the eligible rule and reports the ineligible one — no
    silent partial-promote."""
    await _seed_opensearch(test_session)
    _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    good = await _make_rule(test_session, ip, admin_user, title="Good")
    bad = await _make_rule(test_session, ip, admin_user, title="Bad")
    dev = await _make_env(test_session, "Dev")
    prod = await _make_env(test_session, "Prod")
    await _bind(test_session, good, dev, version=1)  # only Good is in Dev

    resp = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(good.id), str(bad.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "x",
        },
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200, resp.text
    by_id = {r["rule_id"]: r["status"] for r in resp.json()["results"]}
    assert by_id[str(good.id)] == "promoted"
    assert by_id[str(bad.id)] == "ineligible"


# --------------------------------------------------------------------------- #
# B. Per-env dual-control: target requires approval -> file a request (pending)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_promote_into_gated_target_files_request_with_target_env(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)
    captured = _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user,
        versions={1: "pinnedsource"}, live_value="pinnedsource",
    )
    dev = await _make_env(test_session, "Dev")
    prod = await _make_env(test_session, "Prod", require_deploy_approval=True)
    await _bind(test_session, rule, dev, version=1)

    resp = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "needs approval",
        },
        headers=_auth(admin_user),
    )
    # Gated target -> 202 pending_approval (mirrors the deploy gate), so the
    # frontend routes to the "submitted for approval" flow, not "applied".
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "pending_approval"
    assert body["deployment_request_id"] is not None
    assert body["results"][0]["status"] == "pending"
    assert body["results"][0]["source_version"] == 1

    # A PENDING request tagged with the target env, pinned to the source version.
    req = (
        await test_session.execute(
            select(DeploymentRequest).where(
                DeploymentRequest.id == uuid.UUID(body["deployment_request_id"])
            )
        )
    ).scalar_one()
    assert req.status == DeploymentRequestStatus.PENDING.value
    assert req.target_environment_id == prod.id
    assert len(req.items) == 1
    assert req.items[0].rule_id == rule.id
    assert req.items[0].version_number == 1

    # Nothing applied yet: no percolator write, no target binding.
    assert "percolator_index" not in captured
    prod_binding = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.environment_id == prod.id
            )
        )
    ).scalar_one_or_none()
    assert prod_binding is None


# --------------------------------------------------------------------------- #
# B2. Approving a promotion request applies INTO the target env
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_approve_promotion_applies_into_target_env(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)
    captured = _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    # The v1 RuleVersion (what Dev pinned) holds 'pinnedsource'; the scalar live
    # yaml_content drifted to 'drifted'. The current version is still v1, so the
    # promotion is NOT stale, and the deployed query proves the PINNED v1 content
    # is applied — never the scalar live content.
    rule = await _make_rule(
        test_session, ip, admin_user, live_value="drifted",
        versions={1: "pinnedsource"},
    )
    dev = await _make_env(test_session, "Dev")
    default_env = await _make_env(test_session, "Production", is_default=True)
    prod = await _make_env(test_session, "Prod", require_deploy_approval=True)
    await _bind(test_session, rule, dev, version=1)

    # Maker (not admin) files the promotion; admin approves.
    maker = await _make_user(test_session, UserRole.ANALYST, "promo-maker@example.com")
    # Analyst needs deploy_rules; grant via admin-equivalent? Use admin as maker
    # would self-block approval. Instead file as maker then approve as admin.
    # Grant deploy to analyst role for this request path.
    from app.services.permissions import set_role_permission
    await set_role_permission(test_session, "analyst", "deploy_rules", True)

    filed = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "promote with approval",
        },
        headers=_auth(maker),
    )
    assert filed.status_code == 202, filed.text
    rid = filed.json()["deployment_request_id"]
    assert rid is not None

    # Admin approves -> applies INTO the target (Prod) env.
    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == DeploymentRequestStatus.APPLIED.value
    assert body["items"][0]["apply_status"] == "ok"

    # Applied into Prod's namespace with the pinned source content (v1).
    assert captured["percolator_index"] == "chad-percolator-prod-promo-push"
    assert "pinnedsource" in str(captured["query"])
    assert "drifted" not in str(captured["query"])

    # The TARGET (Prod) binding is created at the source version; the DEFAULT env
    # was NOT touched (no default binding, scalar columns untouched).
    prod_binding = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.rule_id == rule.id,
                RuleEnvironmentDeployment.environment_id == prod.id,
            )
        )
    ).scalar_one()
    assert prod_binding.deployed_version == 1
    assert prod_binding.status == RuleStatus.DEPLOYED.value

    default_binding = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.rule_id == rule.id,
                RuleEnvironmentDeployment.environment_id == default_env.id,
            )
        )
    ).scalar_one_or_none()
    assert default_binding is None

    await test_session.refresh(rule)
    assert rule.status == RuleStatus.UNDEPLOYED  # scalar/default untouched
    assert rule.deployed_at is None


# --------------------------------------------------------------------------- #
# B3. Stale check on promote-approve (the rule changed after the request)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_stale_blocks_promotion_approval(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)
    _patch_percolator(monkeypatch)

    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user, versions={1: "v1"}, live_value="v1",
    )
    dev = await _make_env(test_session, "Dev")
    prod = await _make_env(test_session, "Prod", require_deploy_approval=True)
    await _bind(test_session, rule, dev, version=1)

    from app.services.permissions import set_role_permission
    await set_role_permission(test_session, "analyst", "deploy_rules", True)
    maker = await _make_user(test_session, UserRole.ANALYST, "stale-maker@example.com")

    filed = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "x",
        },
        headers=_auth(maker),
    )
    rid = filed.json()["deployment_request_id"]

    # A new version lands after the request -> the request is stale (item pinned
    # at v1, rule current version now v2).
    test_session.add(RuleVersion(
        rule_id=rule.id, version_number=2, yaml_content=_YAML.format(title="x", value="v2"),
        changed_by=admin_user.id, change_reason="edit",
    ))
    await test_session.commit()
    # Drop the cached versions collection so the approve path re-reads v2 (matches
    # the existing dual-control stale test's pattern under expire_on_commit=False).
    test_session.expire(rule)

    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 409
    req = (
        await test_session.execute(
            select(DeploymentRequest).where(DeploymentRequest.id == uuid.UUID(rid))
        )
    ).scalar_one()
    assert req.status == DeploymentRequestStatus.STALE.value


# --------------------------------------------------------------------------- #
# Regression: an existing dual-control request (target_environment_id null)
# still applies into the default env via the unchanged path.
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_regression_null_target_request_applies_to_default(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)

    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user, versions={1: "v1"}, live_value="v1",
    )
    # Seed the default env so apply syncs the scalar columns (back-compat path).
    await _make_env(test_session, "Production", is_default=True)

    from app.services.permissions import set_role_permission
    await set_role_permission(test_session, "analyst", "deploy_rules", True)
    maker = await _make_user(test_session, UserRole.ANALYST, "reg-maker@example.com")

    # File a plain dual-control request (no target env) via the generic endpoint.
    filed = await client.post(
        "/api/deployment-requests",
        json={"rule_ids": [str(rule.id)], "change_reason": "x"},
        headers=_auth(maker),
    )
    assert filed.status_code == 201, filed.text
    rid = filed.json()["id"]

    # The created request must have a NULL target env (existing behavior).
    req = (
        await test_session.execute(
            select(DeploymentRequest).where(DeploymentRequest.id == uuid.UUID(rid))
        )
    ).scalar_one()
    assert req.target_environment_id is None

    # apply_sigma_rule_deployment is called with environment=None (default path).
    apply_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", apply_mock
    )

    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == DeploymentRequestStatus.APPLIED.value

    # The environment kwarg passed to apply is None (legacy default env).
    assert apply_mock.await_count == 1
    assert apply_mock.await_args.kwargs.get("environment") is None


# --------------------------------------------------------------------------- #
# Safety: approving a promotion whose target env was DELETED must NOT silently
# fall back to the default env. It fails loudly and applies nothing.
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_approve_promotion_with_deleted_target_env_fails_not_default(
    client, test_session, admin_user, monkeypatch
):
    await _seed_opensearch(test_session)

    ip = await _make_push_pattern(test_session)
    rule = await _make_rule(
        test_session, ip, admin_user, versions={1: "pinnedsource"},
        live_value="pinnedsource",
    )
    dev = await _make_env(test_session, "Dev")
    # A default env exists; if the bug were present, apply would land HERE.
    default_env = await _make_env(test_session, "Production", is_default=True)
    prod = await _make_env(test_session, "Prod", require_deploy_approval=True)
    await _bind(test_session, rule, dev, version=1)

    from app.services.permissions import set_role_permission
    await set_role_permission(test_session, "analyst", "deploy_rules", True)
    maker = await _make_user(test_session, UserRole.ANALYST, "del-maker@example.com")

    filed = await client.post(
        f"/api/environments/{prod.id}/promote",
        json={
            "rule_ids": [str(rule.id)],
            "source_environment_id": str(dev.id),
            "change_reason": "promote with approval",
        },
        headers=_auth(maker),
    )
    assert filed.status_code == 202, filed.text
    rid = filed.json()["deployment_request_id"]

    # The target env is deleted before approval. Use the deployment binding
    # cascade-safe delete via the ORM (mirrors environment deletion).
    target = (
        await test_session.execute(
            select(Environment).where(Environment.id == prod.id)
        )
    ).scalar_one()
    await test_session.delete(target)
    await test_session.commit()

    # apply must NOT be reached at all; spy to prove it.
    apply_spy = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "app.api.deployment_requests.apply_sigma_rule_deployment", apply_spy
    )

    resp = await client.post(
        f"/api/deployment-requests/{rid}/approve", json={}, headers=_auth(admin_user)
    )
    # Fails loudly (409) and never deploys anywhere.
    assert resp.status_code == 409, resp.text
    assert "target environment" in resp.json()["detail"].lower()
    apply_spy.assert_not_awaited()

    # The request is marked FAILED, not APPLIED.
    req = (
        await test_session.execute(
            select(DeploymentRequest).where(DeploymentRequest.id == uuid.UUID(rid))
        )
    ).scalar_one()
    assert req.status == DeploymentRequestStatus.FAILED.value

    # Nothing was written into the default env (the dangerous fallback).
    default_binding = (
        await test_session.execute(
            select(RuleEnvironmentDeployment).where(
                RuleEnvironmentDeployment.rule_id == rule.id,
                RuleEnvironmentDeployment.environment_id == default_env.id,
            )
        )
    ).scalar_one_or_none()
    assert default_binding is None


# --------------------------------------------------------------------------- #
# Guard: source == target is rejected
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_promote_same_source_and_target_rejected(
    client, test_session, admin_user
):
    await _seed_opensearch(test_session)
    env = await _make_env(test_session, "OnlyEnv")
    resp = await client.post(
        f"/api/environments/{env.id}/promote",
        json={
            "rule_ids": [str(uuid.uuid4())],
            "source_environment_id": str(env.id),
            "change_reason": "x",
        },
        headers=_auth(admin_user),
    )
    assert resp.status_code == 400
    assert "differ" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_promote_requires_deploy_permission(client, test_session, normal_user):
    """A viewer (no deploy_rules) cannot promote -> 403."""
    await _seed_opensearch(test_session)
    env = await _make_env(test_session, "Prod")
    src = await _make_env(test_session, "Dev")
    resp = await client.post(
        f"/api/environments/{env.id}/promote",
        json={
            "rule_ids": [str(uuid.uuid4())],
            "source_environment_id": str(src.id),
            "change_reason": "x",
        },
        headers=_auth(normal_user),
    )
    assert resp.status_code == 403
