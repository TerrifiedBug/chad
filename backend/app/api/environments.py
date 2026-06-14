"""Environments API (Model B per-env deployment scopes).

Environments are team-owned scopes for rule *deployments* (a rule is deployed
*into* an environment via a ``RuleEnvironmentDeployment`` binding, not copied).
Listing is team-scoped (own team + global); mutations require
``manage_environments``; delete requires admin and refuses to remove the last or
the default environment. Every mutation is audited (``environment.*``).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_permission_dep
from app.db.session import get_db
from app.models.environment import Environment, RuleEnvironmentDeployment
from app.models.rule import RuleStatus
from app.models.user import User
from app.schemas.environment import (
    EnvironmentCreate,
    EnvironmentResponse,
    EnvironmentUpdate,
)
from app.services.audit import audit_log
from app.services.team_scope import apply_team_scope, can_access_resource
from app.utils.request import get_client_ip

router = APIRouter(prefix="/environments", tags=["environments"])


async def _get_environment_or_404(db: AsyncSession, environment_id: UUID) -> Environment:
    env = (
        await db.execute(select(Environment).where(Environment.id == environment_id))
    ).scalar_one_or_none()
    if env is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found"
        )
    return env


async def _deploy_counts(db: AsyncSession) -> dict[UUID, tuple[int, int]]:
    """Per-environment (rule_count, deployed_count) keyed by environment_id.

    ``rule_count`` = bindings that exist; ``deployed_count`` = bindings whose
    status is currently 'deployed'. One grouped query for the whole list.
    """
    total_rows = await db.execute(
        select(
            RuleEnvironmentDeployment.environment_id,
            func.count(RuleEnvironmentDeployment.id),
        ).group_by(RuleEnvironmentDeployment.environment_id)
    )
    totals = {env_id: count for env_id, count in total_rows.all()}

    deployed_rows = await db.execute(
        select(
            RuleEnvironmentDeployment.environment_id,
            func.count(RuleEnvironmentDeployment.id),
        )
        .where(RuleEnvironmentDeployment.status == RuleStatus.DEPLOYED.value)
        .group_by(RuleEnvironmentDeployment.environment_id)
    )
    deployed = {env_id: count for env_id, count in deployed_rows.all()}

    return {
        env_id: (totals.get(env_id, 0), deployed.get(env_id, 0))
        for env_id in set(totals) | set(deployed)
    }


def _to_response(env: Environment, counts: tuple[int, int]) -> EnvironmentResponse:
    resp = EnvironmentResponse.model_validate(env)
    resp.rule_count, resp.deployed_count = counts
    return resp


async def _unset_other_defaults(
    db: AsyncSession, team_id: UUID | None, keep_id: UUID | None
) -> None:
    """Clear is_default on the team's other environments (single default per team)."""
    stmt = select(Environment).where(
        Environment.is_default.is_(True),
        (
            Environment.team_id == team_id
            if team_id is not None
            else Environment.team_id.is_(None)
        ),
    )
    if keep_id is not None:
        stmt = stmt.where(Environment.id != keep_id)
    for other in (await db.execute(stmt)).scalars().all():
        other.is_default = False


@router.get("", response_model=list[EnvironmentResponse])
async def list_environments(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """List environments visible to the user (own team + global), with counts."""
    stmt = apply_team_scope(select(Environment), Environment, current_user)
    stmt = stmt.order_by(Environment.name)
    envs = list((await db.execute(stmt)).scalars().all())
    counts = await _deploy_counts(db)
    return [_to_response(env, counts.get(env.id, (0, 0))) for env in envs]


@router.get("/{environment_id}", response_model=EnvironmentResponse)
async def get_environment(
    environment_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    env = await _get_environment_or_404(db, environment_id)
    if not can_access_resource(env, current_user):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found"
        )
    counts = await _deploy_counts(db)
    return _to_response(env, counts.get(env.id, (0, 0)))


@router.post("", response_model=EnvironmentResponse, status_code=status.HTTP_201_CREATED)
async def create_environment(
    data: EnvironmentCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_environments"))],
):
    # Non-admins can only create environments for their own team.
    from app.models.user import UserRole

    team_id = data.team_id
    if current_user.role != UserRole.ADMIN:
        team_id = current_user.team_id

    env = Environment(
        name=data.name,
        description=data.description,
        team_id=team_id,
        is_default=data.is_default,
        require_deploy_approval=data.require_deploy_approval,
        opensearch_index_prefix=data.opensearch_index_prefix,
        color=data.color,
    )
    # Setting a new default unsets the team's other defaults.
    if data.is_default:
        await _unset_other_defaults(db, team_id, keep_id=None)
    db.add(env)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An environment with that name already exists for this team",
        ) from None
    await db.refresh(env)
    await audit_log(
        db, current_user.id, "environment.created", "environment", str(env.id),
        {"name": env.name, "is_default": env.is_default, "team_id": str(team_id) if team_id else None},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return _to_response(env, (0, 0))


@router.patch("/{environment_id}", response_model=EnvironmentResponse)
async def update_environment(
    environment_id: UUID,
    data: EnvironmentUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_environments"))],
):
    env = await _get_environment_or_404(db, environment_id)
    if not can_access_resource(env, current_user):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found"
        )

    update_data = data.model_dump(exclude_unset=True)

    # Setting is_default true unsets the team's other defaults.
    if update_data.get("is_default") is True:
        await _unset_other_defaults(db, env.team_id, keep_id=env.id)

    for field, value in update_data.items():
        setattr(env, field, value)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An environment with that name already exists for this team",
        ) from None
    await db.refresh(env)
    await audit_log(
        db, current_user.id, "environment.updated", "environment", str(env.id),
        {"name": env.name, "changes": list(update_data.keys())},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    counts = await _deploy_counts(db)
    return _to_response(env, counts.get(env.id, (0, 0)))


@router.delete("/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_environment(
    environment_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    env = await _get_environment_or_404(db, environment_id)

    # Refuse to delete the default environment (would orphan the default scope).
    if env.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the default environment",
        )

    # Refuse to delete the last remaining environment.
    total = (await db.execute(select(func.count(Environment.id)))).scalar() or 0
    if total <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the last remaining environment",
        )

    # Bindings cascade on delete (FK ondelete=CASCADE).
    await db.delete(env)
    await audit_log(
        db, admin.id, "environment.deleted", "environment", str(environment_id),
        {"name": env.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
