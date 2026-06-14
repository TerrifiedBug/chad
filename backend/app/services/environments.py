"""Environment resolution + per-env deployment binding helpers (Model B).

Active-environment resolution order (header-optional so existing clients keep
today's behavior):
  1. explicit ``X-CHAD-Environment`` header (env id) — must be visible to the user
  2. the user's team default environment
  3. the global default environment (team_id NULL, is_default true)

The default environment preserves the legacy percolator namespace and mirrors
its bindings into the scalar ``Rule.deployed_*``/``status`` columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.environment import Environment, RuleEnvironmentDeployment
from app.models.rule import Rule
from app.models.user import User, UserRole


async def get_default_environment(db: AsyncSession) -> Environment | None:
    """Return the global default environment (team_id NULL, is_default true)."""
    result = await db.execute(
        select(Environment)
        .where(Environment.is_default.is_(True), Environment.team_id.is_(None))
        .limit(1)
    )
    env = result.scalar_one_or_none()
    if env is not None:
        return env
    # Fallback: any default env (covers installs where the default is team-scoped).
    result = await db.execute(
        select(Environment).where(Environment.is_default.is_(True)).limit(1)
    )
    return result.scalar_one_or_none()


async def get_team_default_environment(
    db: AsyncSession, team_id: uuid.UUID | None
) -> Environment | None:
    """Default environment owned by ``team_id`` (None when the team has none)."""
    if team_id is None:
        return None
    result = await db.execute(
        select(Environment)
        .where(Environment.is_default.is_(True), Environment.team_id == team_id)
        .limit(1)
    )
    return result.scalar_one_or_none()


def _user_can_see_env(env: Environment, user: User) -> bool:
    """Whether ``user`` may use ``env`` (admin: any; others: own team or global)."""
    if user.role == UserRole.ADMIN:
        return True
    return env.team_id is None or env.team_id == user.team_id


async def resolve_active_environment(
    db: AsyncSession,
    user: User,
    header_value: str | None,
) -> Environment | None:
    """Resolve the active environment for a request.

    Header (env id) -> user's team default -> global default. Header-optional:
    absent/invalid header falls through to the team/global default, which is
    today's behavior. Returns None only when no environment exists at all
    (pre-migration / fresh install), in which case callers treat the active env
    as the legacy default (None == legacy namespace + scalar sync).
    """
    if header_value:
        try:
            env_id = uuid.UUID(header_value)
        except (ValueError, AttributeError):
            env_id = None
        if env_id is not None:
            result = await db.execute(
                select(Environment).where(Environment.id == env_id)
            )
            env = result.scalar_one_or_none()
            if env is not None and _user_can_see_env(env, user):
                return env

    team_default = await get_team_default_environment(db, user.team_id)
    if team_default is not None:
        return team_default

    return await get_default_environment(db)


async def get_environment_deployment(
    db: AsyncSession, rule_id: uuid.UUID, environment_id: uuid.UUID
) -> RuleEnvironmentDeployment | None:
    """Fetch the binding for (rule, environment), or None."""
    result = await db.execute(
        select(RuleEnvironmentDeployment).where(
            RuleEnvironmentDeployment.rule_id == rule_id,
            RuleEnvironmentDeployment.environment_id == environment_id,
        )
    )
    return result.scalar_one_or_none()


async def upsert_environment_deployment(
    db: AsyncSession,
    *,
    rule_id: uuid.UUID,
    environment_id: uuid.UUID,
    status: str,
    deployed_version: int | None,
    deployed_at: datetime | None,
    snooze_until: datetime | None = None,
    snooze_indefinite: bool = False,
) -> RuleEnvironmentDeployment:
    """Create or update the (rule, environment) deployment binding.

    Does NOT commit — the caller owns the transaction so the binding write is
    atomic with the rest of the deploy/undeploy/snooze path.
    """
    binding = await get_environment_deployment(db, rule_id, environment_id)
    if binding is None:
        binding = RuleEnvironmentDeployment(
            rule_id=rule_id,
            environment_id=environment_id,
            status=status,
            deployed_version=deployed_version,
            deployed_at=deployed_at,
            snooze_until=snooze_until,
            snooze_indefinite=snooze_indefinite,
        )
        db.add(binding)
    else:
        binding.status = status
        binding.deployed_version = deployed_version
        binding.deployed_at = deployed_at
        binding.snooze_until = snooze_until
        binding.snooze_indefinite = snooze_indefinite
    await db.flush()
    return binding


async def environment_needs_redeploy(
    db: AsyncSession, rule: Rule, environment_id: uuid.UUID
) -> bool:
    """Per-env needs_redeploy = binding.deployed_version != rule.current_version."""
    binding = await get_environment_deployment(db, rule.id, environment_id)
    if binding is None or binding.deployed_version is None:
        return False
    current_version = rule.versions[0].version_number if rule.versions else 1
    return binding.deployed_version != current_version
