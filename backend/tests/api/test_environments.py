"""Tests for Environments (Model B: per-env deployment binding).

Covers: migration backfill (deployed rule -> default-env binding, scalar kept),
default-env percolator == legacy name, deploy into a non-default env writes its
binding + namespace without touching another env, per-env needs_redeploy, env
CRUD + manage_environments RBAC + block-delete-default/last, and active-env
header resolution (absent -> default).
"""

import importlib.util
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.core.security import create_access_token
from app.models.environment import Environment, RuleEnvironmentDeployment
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.user import User

_VALID_YAML = (
    "title: {title}\nlogsource:\n  category: test\n"
    "detection:\n  selection:\n    fieldA: value\n  condition: selection\n"
)


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_push_pattern(session, name="env-push") -> IndexPattern:
    ip = IndexPattern(
        id=uuid.uuid4(), name=name, pattern=f"{name}-*",
        percolator_index=f".perc-{name}", mode="push",
    )
    session.add(ip)
    await session.commit()
    await session.refresh(ip)
    return ip


async def _make_rule(session, ip, user, title="Env Rule", *, version=1,
                     status=RuleStatus.UNDEPLOYED, deployed_version=None):
    deployed_at = datetime.now(UTC) if deployed_version is not None else None
    rule = Rule(
        id=uuid.uuid4(), title=title, yaml_content=_VALID_YAML.format(title=title),
        severity="low", status=status, source=RuleSource.USER,
        index_pattern_id=ip.id, created_by=user.id, deployed_version=deployed_version,
        deployed_at=deployed_at,
    )
    session.add(rule)
    await session.flush()
    session.add(RuleVersion(
        rule_id=rule.id, version_number=version,
        yaml_content=_VALID_YAML.format(title=title),
        changed_by=user.id, change_reason="init",
    ))
    await session.commit()
    await session.refresh(rule)
    return rule


async def _make_default_env(session, name="Production") -> Environment:
    env = Environment(id=uuid.uuid4(), name=name, is_default=True, team_id=None)
    session.add(env)
    await session.commit()
    await session.refresh(env)
    return env


async def _make_env(session, name, *, is_default=False, team_id=None,
                    require_deploy_approval=False, prefix=None) -> Environment:
    env = Environment(
        id=uuid.uuid4(), name=name, is_default=is_default, team_id=team_id,
        require_deploy_approval=require_deploy_approval, opensearch_index_prefix=prefix,
    )
    session.add(env)
    await session.commit()
    await session.refresh(env)
    return env


async def _make_binding(session, rule, env, *, status=RuleStatus.DEPLOYED.value,
                        deployed_version=1) -> RuleEnvironmentDeployment:
    binding = RuleEnvironmentDeployment(
        rule_id=rule.id, environment_id=env.id, deployed_version=deployed_version,
        deployed_at=datetime.now(UTC), status=status,
    )
    session.add(binding)
    await session.commit()
    await session.refresh(binding)
    return binding


# --------------------------------------------------------------------------- #
# Migration backfill (data-migration helper run against a live connection)
# --------------------------------------------------------------------------- #
def _load_migration_module():
    path = (
        Path(__file__).resolve().parents[2]
        / "alembic" / "versions" / "20260614c_add_environments.py"
    )
    spec = importlib.util.spec_from_file_location("_env_migration_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _run_backfill(test_session):
    module = _load_migration_module()

    def _apply(sync_conn):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module._backfill_default_environment()

    raw_conn = await test_session.connection()
    await raw_conn.run_sync(_apply)
    await test_session.commit()


class TestMigrationBackfill:
    @pytest.mark.asyncio
    async def test_deployed_rule_gets_default_env_binding_scalar_kept(
        self, test_session, admin_user
    ):
        """A currently-deployed rule -> a default-env binding mirroring its
        scalar deployed_*/status, and the scalar columns are KEPT."""
        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(
            test_session, ip, admin_user, title="Deployed",
            status=RuleStatus.DEPLOYED, deployed_version=1,
        )

        await _run_backfill(test_session)

        # One global default env was created.
        default_env = (
            await test_session.execute(
                select(Environment).where(Environment.is_default.is_(True))
            )
        ).scalar_one()
        assert default_env.name == "Production"
        assert default_env.team_id is None

        # The deployed rule got a binding into the default env.
        binding = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id
                )
            )
        ).scalar_one()
        assert binding.environment_id == default_env.id
        assert binding.deployed_version == 1
        assert binding.status == RuleStatus.DEPLOYED.value
        assert binding.deployed_at is not None

        # Scalar columns on the rule are KEPT (default-env mirror, back-compat).
        await test_session.refresh(rule)
        assert rule.deployed_at is not None
        assert rule.deployed_version == 1
        assert rule.status == RuleStatus.DEPLOYED

    @pytest.mark.asyncio
    async def test_undeployed_rule_gets_no_binding(self, test_session, admin_user):
        """An undeployed rule (deployed_at NULL) is not backfilled."""
        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(test_session, ip, admin_user, title="Undeployed")

        await _run_backfill(test_session)

        count = (
            await test_session.execute(
                text(
                    "SELECT COUNT(*) FROM rule_environment_deployments "
                    "WHERE rule_id = :rid"
                ),
                {"rid": str(rule.id)},
            )
        ).scalar()
        assert count == 0

    @pytest.mark.asyncio
    async def test_backfill_idempotent(self, test_session, admin_user):
        """Re-running the backfill does not create a second env or duplicate bindings."""
        ip = await _make_push_pattern(test_session)
        await _make_rule(
            test_session, ip, admin_user, title="Deployed",
            status=RuleStatus.DEPLOYED, deployed_version=1,
        )

        await _run_backfill(test_session)
        await _run_backfill(test_session)

        env_count = (
            await test_session.execute(text("SELECT COUNT(*) FROM environments"))
        ).scalar()
        binding_count = (
            await test_session.execute(
                text("SELECT COUNT(*) FROM rule_environment_deployments")
            )
        ).scalar()
        assert env_count == 1
        assert binding_count == 1


# --------------------------------------------------------------------------- #
# Percolator per-env namespace (default == legacy; non-default prefixed)
# --------------------------------------------------------------------------- #
class TestPercolatorNamespaceWithEnv:
    @pytest.mark.asyncio
    async def test_default_env_percolator_is_legacy_name(self, test_session):
        from unittest.mock import MagicMock

        from app.services.percolator import PercolatorService

        default_env = await _make_default_env(test_session)
        svc = PercolatorService(MagicMock())
        # Default env MUST resolve to the existing legacy name (no prefix, no re-index).
        assert (
            svc.get_percolator_index_name("logs-windows-*", environment=default_env)
            == "chad-percolator-logs-windows"
        )
        # None (legacy callers) also resolves to the legacy name.
        assert (
            svc.get_percolator_index_name("logs-windows-*")
            == "chad-percolator-logs-windows"
        )

    @pytest.mark.asyncio
    async def test_non_default_env_percolator_is_prefixed(self, test_session):
        from unittest.mock import MagicMock

        from app.services.percolator import PercolatorService

        dev = await _make_env(test_session, "Dev")
        svc = PercolatorService(MagicMock())
        assert (
            svc.get_percolator_index_name("logs-windows-*", environment=dev)
            == "chad-percolator-dev-logs-windows"
        )


# --------------------------------------------------------------------------- #
# Deploy into a specific env writes its binding + namespace, not another env's
# --------------------------------------------------------------------------- #
class TestDeployIntoEnvironment:
    @pytest.mark.asyncio
    async def test_deploy_into_non_default_env_writes_binding_and_namespace(
        self, test_session, admin_user, monkeypatch
    ):
        """Deploying into env-X writes binding-X to env-X's percolator namespace
        and leaves env-Y untouched. The scalar Rule.deployed_* stays null (X is
        not the default env)."""
        from app.services.deployment import apply_sigma_rule_deployment

        monkeypatch.setattr(
            "app.services.deployment.get_index_fields", lambda *a, **k: ["fieldA"]
        )

        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(test_session, ip, admin_user, title="MultiEnv")
        env_x = await _make_env(test_session, "EnvX")
        # env_y exists so the test can assert it is NOT touched by the env-X deploy.
        await _make_env(test_session, "EnvY")

        captured: dict = {}

        def _fake_deploy(self, *, percolator_index, rule_id, query, title, severity, tags):
            captured["percolator_index"] = percolator_index
            captured["rule_id"] = rule_id

        monkeypatch.setattr(
            "app.services.percolator.PercolatorService.deploy_rule", _fake_deploy
        )
        monkeypatch.setattr(
            "app.services.percolator.PercolatorService.ensure_percolator_index",
            lambda self, *a, **k: None,
        )

        # Reload rule with relationships eager-loaded (apply requires them).
        from sqlalchemy.orm import selectinload
        rule = (
            await test_session.execute(
                select(Rule).where(Rule.id == rule.id).options(
                    selectinload(Rule.index_pattern), selectinload(Rule.versions)
                )
            )
        ).scalar_one()

        from unittest.mock import MagicMock
        await apply_sigma_rule_deployment(
            test_session, MagicMock(), rule,
            actor_id=admin_user.id, change_reason="x", environment=env_x,
        )

        # Wrote to env-X's prefixed namespace.
        assert captured["percolator_index"] == "chad-percolator-envx-env-push"

        # Binding exists for env-X, not env-Y.
        bindings = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id
                )
            )
        ).scalars().all()
        assert len(bindings) == 1
        assert bindings[0].environment_id == env_x.id
        assert bindings[0].status == RuleStatus.DEPLOYED.value
        assert bindings[0].deployed_version == 1

        # Non-default env: scalar columns are NOT touched (still undeployed).
        await test_session.refresh(rule)
        assert rule.deployed_at is None
        assert rule.status == RuleStatus.UNDEPLOYED

    @pytest.mark.asyncio
    async def test_deploy_into_default_env_syncs_scalar_and_legacy_namespace(
        self, test_session, admin_user, monkeypatch
    ):
        """Deploying into the default env uses the legacy namespace AND keeps the
        scalar Rule.deployed_*/status in sync (back-compat == today)."""
        from app.services.deployment import apply_sigma_rule_deployment

        monkeypatch.setattr(
            "app.services.deployment.get_index_fields", lambda *a, **k: ["fieldA"]
        )
        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(test_session, ip, admin_user, title="DefaultDeploy")
        default_env = await _make_default_env(test_session)

        captured: dict = {}
        monkeypatch.setattr(
            "app.services.percolator.PercolatorService.deploy_rule",
            lambda self, **kw: captured.update(kw),
        )
        monkeypatch.setattr(
            "app.services.percolator.PercolatorService.ensure_percolator_index",
            lambda self, *a, **k: None,
        )

        from sqlalchemy.orm import selectinload
        rule = (
            await test_session.execute(
                select(Rule).where(Rule.id == rule.id).options(
                    selectinload(Rule.index_pattern), selectinload(Rule.versions)
                )
            )
        ).scalar_one()

        from unittest.mock import MagicMock
        await apply_sigma_rule_deployment(
            test_session, MagicMock(), rule,
            actor_id=admin_user.id, change_reason="x", environment=default_env,
        )

        # Legacy (unprefixed) namespace.
        assert captured["percolator_index"] == "chad-percolator-env-push"

        # Scalar columns synced (back-compat).
        await test_session.refresh(rule)
        assert rule.deployed_at is not None
        assert rule.deployed_version == 1
        assert rule.status == RuleStatus.DEPLOYED

        # Binding also written for the default env.
        binding = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id
                )
            )
        ).scalar_one()
        assert binding.environment_id == default_env.id


# --------------------------------------------------------------------------- #
# Per-env needs_redeploy
# --------------------------------------------------------------------------- #
class TestPerEnvNeedsRedeploy:
    @pytest.mark.asyncio
    async def test_needs_redeploy_when_binding_version_behind(
        self, test_session, admin_user
    ):
        from sqlalchemy.orm import selectinload

        from app.services.environments import environment_needs_redeploy

        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(test_session, ip, admin_user, title="Redeploy", version=2)
        env = await _make_env(test_session, "EnvA")

        # Binding pinned at v1 while the rule's current version is 2.
        test_session.add(RuleEnvironmentDeployment(
            rule_id=rule.id, environment_id=env.id, deployed_version=1,
            deployed_at=datetime.now(UTC), status=RuleStatus.DEPLOYED.value,
        ))
        await test_session.commit()

        rule = (
            await test_session.execute(
                select(Rule).where(Rule.id == rule.id).options(selectinload(Rule.versions))
            )
        ).scalar_one()
        assert await environment_needs_redeploy(test_session, rule, env.id) is True

    @pytest.mark.asyncio
    async def test_no_redeploy_when_binding_current(self, test_session, admin_user):
        from sqlalchemy.orm import selectinload

        from app.services.environments import environment_needs_redeploy

        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(test_session, ip, admin_user, title="Current", version=2)
        env = await _make_env(test_session, "EnvB")
        test_session.add(RuleEnvironmentDeployment(
            rule_id=rule.id, environment_id=env.id, deployed_version=2,
            deployed_at=datetime.now(UTC), status=RuleStatus.DEPLOYED.value,
        ))
        await test_session.commit()

        rule = (
            await test_session.execute(
                select(Rule).where(Rule.id == rule.id).options(selectinload(Rule.versions))
            )
        ).scalar_one()
        assert await environment_needs_redeploy(test_session, rule, env.id) is False


# --------------------------------------------------------------------------- #
# Environments CRUD + manage_environments gate + block-delete-default/last
# --------------------------------------------------------------------------- #
class TestEnvironmentsCrud:
    @pytest.mark.asyncio
    async def test_admin_can_create_list_get(self, client, admin_user, test_session):
        await _make_default_env(test_session)
        resp = await client.post(
            "/api/environments", json={"name": "Staging"}, headers=_auth(admin_user)
        )
        assert resp.status_code == 201, resp.text
        env_id = resp.json()["id"]

        listed = await client.get("/api/environments", headers=_auth(admin_user))
        assert listed.status_code == 200
        names = {e["name"] for e in listed.json()}
        assert {"Production", "Staging"} <= names

        one = await client.get(f"/api/environments/{env_id}", headers=_auth(admin_user))
        assert one.status_code == 200
        assert one.json()["name"] == "Staging"

    @pytest.mark.asyncio
    async def test_viewer_cannot_create(self, client, normal_user):
        """Viewer lacks manage_environments -> 403."""
        resp = await client.post(
            "/api/environments", json={"name": "Nope"}, headers=_auth(normal_user)
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_set_default_unsets_others(self, client, admin_user, test_session):
        default_env = await _make_default_env(test_session)
        other = await _make_env(test_session, "Dev")

        resp = await client.patch(
            f"/api/environments/{other.id}",
            json={"is_default": True},
            headers=_auth(admin_user),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_default"] is True

        await test_session.refresh(default_env)
        assert default_env.is_default is False

    @pytest.mark.asyncio
    async def test_cannot_delete_default(self, client, admin_user, test_session):
        default_env = await _make_default_env(test_session)
        await _make_env(test_session, "Dev")  # ensure not the last one
        resp = await client.delete(
            f"/api/environments/{default_env.id}", headers=_auth(admin_user)
        )
        assert resp.status_code == 400
        assert "default" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_cannot_delete_last_environment(self, client, admin_user, test_session):
        # A single non-default env: deleting it would leave zero -> blocked.
        env = await _make_env(test_session, "Only")
        resp = await client.delete(
            f"/api/environments/{env.id}", headers=_auth(admin_user)
        )
        assert resp.status_code == 400
        assert "last" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_non_default_succeeds(self, client, admin_user, test_session):
        await _make_default_env(test_session)
        dev = await _make_env(test_session, "Dev")
        resp = await client.delete(
            f"/api/environments/{dev.id}", headers=_auth(admin_user)
        )
        assert resp.status_code == 204
        remaining = (
            await test_session.execute(select(Environment).where(Environment.id == dev.id))
        ).scalar_one_or_none()
        assert remaining is None


# --------------------------------------------------------------------------- #
# Active-environment header resolution (absent -> default)
# --------------------------------------------------------------------------- #
class TestActiveEnvResolution:
    @pytest.mark.asyncio
    async def test_no_header_resolves_global_default(self, test_session, admin_user):
        from app.services.environments import resolve_active_environment

        default_env = await _make_default_env(test_session)
        await _make_env(test_session, "Dev")

        env = await resolve_active_environment(test_session, admin_user, None)
        assert env is not None
        assert env.id == default_env.id
        assert env.is_default is True

    @pytest.mark.asyncio
    async def test_header_selects_named_environment(self, test_session, admin_user):
        from app.services.environments import resolve_active_environment

        await _make_default_env(test_session)
        dev = await _make_env(test_session, "Dev")

        env = await resolve_active_environment(test_session, admin_user, str(dev.id))
        assert env is not None
        assert env.id == dev.id

    @pytest.mark.asyncio
    async def test_invalid_header_falls_back_to_default(self, test_session, admin_user):
        from app.services.environments import resolve_active_environment

        default_env = await _make_default_env(test_session)
        env = await resolve_active_environment(test_session, admin_user, "not-a-uuid")
        assert env is not None
        assert env.id == default_env.id

    @pytest.mark.asyncio
    async def test_no_environments_resolves_none(self, test_session, admin_user):
        from app.services.environments import resolve_active_environment

        # Fresh install (pre-migration): no env at all -> None (legacy default).
        env = await resolve_active_environment(test_session, admin_user, None)
        assert env is None


# --------------------------------------------------------------------------- #
# Snooze / unsnooze with a SEEDED default env and NO header (prod parity).
#
# The create_all test harness seeds NO default environment, so prior tests hit
# the active_env=None branch and missed the prod NameError where snooze_rule
# referenced env_binding on the default-env path. These tests seed a default
# Environment row (like the migration) so active_env resolves to it, exercising
# the exact default-env code path that runs in prod.
# --------------------------------------------------------------------------- #
class TestSnoozeUnsnoozeWithDefaultEnv:
    @staticmethod
    def _override_optional_os():
        """Override get_opensearch_client_optional with a MagicMock client.

        Snooze/unsnooze read the percolator via the optional client; a real one
        is unavailable in tests. Returns a teardown to clear the override.
        """
        from unittest.mock import MagicMock

        from app.api.deps import get_opensearch_client_optional
        from app.main import app

        app.dependency_overrides[get_opensearch_client_optional] = lambda: MagicMock()

        def _teardown():
            app.dependency_overrides.pop(get_opensearch_client_optional, None)

        return _teardown

    @pytest.mark.asyncio
    async def test_default_env_snooze_no_header_does_not_crash(
        self, client, test_session, admin_user
    ):
        """REGRESSION: a deployed rule snoozed with NO X-CHAD-Environment header
        resolves active_env to the seeded default env. This previously raised
        NameError (env_binding referenced but unassigned on the default path)."""
        default_env = await _make_default_env(test_session)
        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(
            test_session, ip, admin_user, title="DefaultSnooze",
            status=RuleStatus.DEPLOYED, deployed_version=1,
        )
        await _make_binding(test_session, rule, default_env)

        teardown = self._override_optional_os()
        try:
            resp = await client.post(
                f"/api/rules/{rule.id}/snooze",
                json={"hours": 4, "change_reason": "noise"},
                headers=_auth(admin_user),  # NO X-CHAD-Environment header
            )
        finally:
            teardown()

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "snoozed"

        # Scalar columns synced (default-env back-compat).
        await test_session.refresh(rule)
        assert rule.status == RuleStatus.SNOOZED
        assert rule.snooze_until is not None

        # Default-env binding reflects the snooze.
        binding = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id,
                    RuleEnvironmentDeployment.environment_id == default_env.id,
                )
            )
        ).scalar_one()
        assert binding.status == RuleStatus.SNOOZED.value
        # Pinned version carried forward from the scalar columns.
        assert binding.deployed_version == 1

    @pytest.mark.asyncio
    async def test_default_env_unsnooze_no_header_does_not_crash(
        self, client, test_session, admin_user
    ):
        """REGRESSION: unsnooze with NO header resolves to the seeded default env
        and restores the deployed state without crashing."""
        default_env = await _make_default_env(test_session)
        ip = await _make_push_pattern(test_session)
        rule = await _make_rule(
            test_session, ip, admin_user, title="DefaultUnsnooze",
            status=RuleStatus.SNOOZED, deployed_version=1,
        )
        await _make_binding(
            test_session, rule, default_env, status=RuleStatus.SNOOZED.value
        )

        teardown = self._override_optional_os()
        try:
            resp = await client.post(
                f"/api/rules/{rule.id}/unsnooze",
                json={"change_reason": "back on"},
                headers=_auth(admin_user),  # NO X-CHAD-Environment header
            )
        finally:
            teardown()

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "deployed"

        await test_session.refresh(rule)
        assert rule.status == RuleStatus.DEPLOYED
        assert rule.snooze_until is None

        binding = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id,
                    RuleEnvironmentDeployment.environment_id == default_env.id,
                )
            )
        ).scalar_one()
        assert binding.status == RuleStatus.DEPLOYED.value
        assert binding.snooze_until is None

    @pytest.mark.asyncio
    async def test_non_default_env_snooze_then_unsnooze(
        self, client, test_session, admin_user
    ):
        """Snooze + unsnooze into a NON-default env via the header: only that
        env's binding changes; the scalar Rule columns stay untouched."""
        default_env = await _make_default_env(test_session)
        dev = await _make_env(test_session, "Dev")
        ip = await _make_push_pattern(test_session)
        # Rule deployed in the default env (scalar) AND in Dev (binding only).
        rule = await _make_rule(
            test_session, ip, admin_user, title="MultiEnvSnooze",
            status=RuleStatus.DEPLOYED, deployed_version=1,
        )
        await _make_binding(test_session, rule, default_env)
        await _make_binding(test_session, rule, dev)

        header = {**_auth(admin_user), "X-CHAD-Environment": str(dev.id)}

        teardown = self._override_optional_os()
        try:
            snooze = await client.post(
                f"/api/rules/{rule.id}/snooze",
                json={"indefinite": True, "change_reason": "dev noise"},
                headers=header,
            )
            assert snooze.status_code == 200, snooze.text

            # Dev binding is snoozed; the default-env binding + scalar untouched.
            await test_session.refresh(rule)
            assert rule.status == RuleStatus.DEPLOYED  # scalar (default env) unchanged
            dev_binding = (
                await test_session.execute(
                    select(RuleEnvironmentDeployment).where(
                        RuleEnvironmentDeployment.rule_id == rule.id,
                        RuleEnvironmentDeployment.environment_id == dev.id,
                    )
                )
            ).scalar_one()
            assert dev_binding.status == RuleStatus.SNOOZED.value
            assert dev_binding.snooze_indefinite is True
            default_binding = (
                await test_session.execute(
                    select(RuleEnvironmentDeployment).where(
                        RuleEnvironmentDeployment.rule_id == rule.id,
                        RuleEnvironmentDeployment.environment_id == default_env.id,
                    )
                )
            ).scalar_one()
            assert default_binding.status == RuleStatus.DEPLOYED.value

            unsnooze = await client.post(
                f"/api/rules/{rule.id}/unsnooze",
                json={"change_reason": "dev back"},
                headers=header,
            )
            assert unsnooze.status_code == 200, unsnooze.text
        finally:
            teardown()

        await test_session.refresh(rule)
        assert rule.status == RuleStatus.DEPLOYED  # still untouched
        dev_binding = (
            await test_session.execute(
                select(RuleEnvironmentDeployment).where(
                    RuleEnvironmentDeployment.rule_id == rule.id,
                    RuleEnvironmentDeployment.environment_id == dev.id,
                )
            )
        ).scalar_one()
        assert dev_binding.status == RuleStatus.DEPLOYED.value
        assert dev_binding.snooze_until is None

    @pytest.mark.asyncio
    async def test_non_default_env_snooze_blocked_when_not_deployed_there(
        self, client, test_session, admin_user
    ):
        """Snoozing in a non-default env where the rule has no deployed binding
        is rejected (mirrors the undeployed-rule guard), not a crash."""
        await _make_default_env(test_session)
        dev = await _make_env(test_session, "Dev")
        ip = await _make_push_pattern(test_session)
        # Deployed in default (scalar) but NOT in Dev (no Dev binding).
        rule = await _make_rule(
            test_session, ip, admin_user, title="NotInDev",
            status=RuleStatus.DEPLOYED, deployed_version=1,
        )

        header = {**_auth(admin_user), "X-CHAD-Environment": str(dev.id)}
        teardown = self._override_optional_os()
        try:
            resp = await client.post(
                f"/api/rules/{rule.id}/snooze",
                json={"hours": 2, "change_reason": "x"},
                headers=header,
            )
        finally:
            teardown()

        assert resp.status_code == 400
        assert "undeployed" in resp.json()["detail"].lower()
