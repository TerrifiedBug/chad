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
from fastapi.responses import JSONResponse
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_current_user,
    get_opensearch_client,
    require_admin,
    require_permission_dep,
)
from app.db.session import get_db
from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestItem,
    DeploymentRequestKind,
    DeploymentRequestStatus,
)
from app.models.environment import Environment, RuleEnvironmentDeployment
from app.models.rule import Rule, RuleStatus
from app.models.user import User
from app.schemas.environment import (
    EnvironmentCreate,
    EnvironmentResponse,
    EnvironmentUpdate,
    PromoteRequest,
    PromoteResponse,
    PromoteRuleResult,
)
from app.services.audit import audit_log
from app.services.deployment import DeploymentApplyError, apply_sigma_rule_deployment
from app.services.environments import get_environment_deployment
from app.services.sigma import sigma_service
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


# --------------------------------------------------------------------------- #
# Promotion: advance the target env's pinned version to the source env's.
# Model B — the rule definition is never copied; we deploy the SOURCE env's
# pinned version into the TARGET env (target percolator namespace + binding).
# Single-cluster: all envs share the OpenSearch cluster (cross-cluster per-env
# connection is the deferred AC C — follow-up).
# --------------------------------------------------------------------------- #
class _PromoteCandidate:
    """A rule that passed preflight: its source-pinned version + that YAML."""

    __slots__ = ("rule", "source_version", "source_yaml")

    def __init__(self, rule: Rule, source_version: int, source_yaml: str) -> None:
        self.rule = rule
        self.source_version = source_version
        self.source_yaml = source_yaml


async def _promote_preflight(
    db: AsyncSession,
    rule_ids: list[UUID],
    source_env: Environment,
    current_user: User,
) -> tuple[list[_PromoteCandidate], list[PromoteRuleResult]]:
    """Validate each rule is promotable from ``source_env``.

    Eligible (A2): the rule exists, the caller can access it, it is deployed in
    the source env (binding with a non-null ``deployed_version``), that pinned
    version's YAML still exists and translates cleanly. Returns
    ``(candidates, ineligible_results)`` so the caller never partial-promotes
    silently — every rejected rule is reported with a reason.
    """
    rows = await db.execute(
        select(Rule)
        .where(Rule.id.in_(rule_ids))
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rules = {r.id: r for r in rows.scalars().all()}

    candidates: list[_PromoteCandidate] = []
    ineligible: list[PromoteRuleResult] = []

    for rule_id in rule_ids:
        rule = rules.get(rule_id)
        if rule is None:
            ineligible.append(
                PromoteRuleResult(
                    rule_id=rule_id, status="ineligible", reason="Rule not found"
                )
            )
            continue
        if not can_access_resource(rule, current_user):
            ineligible.append(
                PromoteRuleResult(
                    rule_id=rule_id,
                    status="ineligible",
                    reason="You do not have access to this rule",
                )
            )
            continue

        binding = await get_environment_deployment(db, rule.id, source_env.id)
        if binding is None or binding.deployed_version is None or (
            binding.status != RuleStatus.DEPLOYED.value
        ):
            ineligible.append(
                PromoteRuleResult(
                    rule_id=rule_id,
                    status="ineligible",
                    reason=f"Rule is not deployed in the source environment "
                    f"'{source_env.name}'",
                )
            )
            continue

        source_version = binding.deployed_version
        # Explicit + safe: a pinned version that is missing (or somehow
        # duplicated) must surface as ineligible, never crash. Take the first
        # matching RuleVersion's YAML, or None when there is no match.
        matching_versions = [
            v for v in rule.versions if v.version_number == source_version
        ]
        source_yaml = matching_versions[0].yaml_content if matching_versions else None
        if source_yaml is None:
            ineligible.append(
                PromoteRuleResult(
                    rule_id=rule_id,
                    status="ineligible",
                    source_version=source_version,
                    reason=f"Source-deployed version {source_version} no longer exists",
                )
            )
            continue

        # The pinned source version must still translate (A2).
        validation = sigma_service.translate_and_validate(source_yaml)
        if not validation.success:
            errors_str = ", ".join(e.message for e in (validation.errors or []))
            ineligible.append(
                PromoteRuleResult(
                    rule_id=rule_id,
                    status="ineligible",
                    source_version=source_version,
                    reason=f"Source version does not translate: {errors_str}",
                )
            )
            continue

        candidates.append(_PromoteCandidate(rule, source_version, source_yaml))

    return candidates, ineligible


def _source_version_id(rule: Rule, version_number: int) -> UUID | None:
    """The RuleVersion id for ``version_number`` (for pinning a request item)."""
    return next(
        (v.id for v in rule.versions if v.version_number == version_number), None
    )


@router.post("/{target_id}/promote", response_model=PromoteResponse)
async def promote_rules(
    target_id: UUID,
    data: PromoteRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Promote rules' source-env deployment into the target env (Model B).

    For each rule the version currently deployed in ``source_environment_id`` is
    deployed (pinned) into ``target_id`` — the rule definition is untouched.
    Preflight (A2) reports ineligible rules rather than partial-promoting. If the
    target env requires deploy approval (per-env dual-control, B) the eligible
    rules are filed as a single PENDING ``DeploymentRequest`` tagged with the
    target env and 202 is returned; otherwise they are applied immediately.
    """
    target_env = await _get_environment_or_404(db, target_id)
    if not can_access_resource(target_env, current_user):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found"
        )

    source_env = await _get_environment_or_404(db, data.source_environment_id)
    if not can_access_resource(source_env, current_user):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source environment not found",
        )

    if source_env.id == target_env.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source and target environments must differ",
        )

    unique_ids = list(dict.fromkeys(data.rule_ids))
    candidates, ineligible = await _promote_preflight(
        db, unique_ids, source_env, current_user
    )

    # Per-env dual-control (B): the target env gates promotions. File a single
    # request pinned to the SOURCE version and return 202 (like the deploy gate).
    if target_env.require_deploy_approval and candidates:
        req = DeploymentRequest(
            requested_by=current_user.id,
            team_id=current_user.team_id,
            change_reason=data.change_reason,
            status=DeploymentRequestStatus.PENDING.value,
            target_environment_id=target_env.id,
        )
        for cand in candidates:
            req.items.append(
                DeploymentRequestItem(
                    rule_id=cand.rule.id,
                    rule_version_id=_source_version_id(cand.rule, cand.source_version),
                    version_number=cand.source_version,
                    kind=DeploymentRequestKind.SIGMA.value,
                )
            )
        db.add(req)
        await db.flush()
        await audit_log(
            db, current_user.id, "promotion.requested", "deployment_request",
            str(req.id),
            {
                "target_environment_id": str(target_env.id),
                "source_environment_id": str(source_env.id),
                "rule_ids": [str(c.rule.id) for c in candidates],
                "rule_count": len(candidates),
                "change_reason": data.change_reason,
            },
            ip_address=get_client_ip(request),
        )
        await db.commit()

        # 202 pending_approval: mirrors the deploy gate's shape so the frontend
        # discriminates "submitted for approval" (202) from "applied" (200).
        results = [
            PromoteRuleResult(
                rule_id=c.rule.id, status="pending", source_version=c.source_version
            )
            for c in candidates
        ] + ineligible
        payload = PromoteResponse(
            target_environment_id=target_env.id,
            source_environment_id=source_env.id,
            deployment_request_id=req.id,
            results=results,
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "pending_approval",
                "deployment_request_id": str(req.id),
                **payload.model_dump(mode="json"),
            },
        )

    # Ungated path: apply each candidate's pinned source version into the target
    # env immediately via the shared deploy service.
    results: list[PromoteRuleResult] = []
    for cand in candidates:
        try:
            await apply_sigma_rule_deployment(
                db,
                os_client,
                cand.rule,
                actor_id=current_user.id,
                change_reason=data.change_reason,
                request_ip=get_client_ip(request),
                pinned_yaml=cand.source_yaml,
                pinned_version=cand.source_version,
                environment=target_env,
            )
            results.append(
                PromoteRuleResult(
                    rule_id=cand.rule.id,
                    status="promoted",
                    source_version=cand.source_version,
                )
            )
        except DeploymentApplyError as e:
            results.append(
                PromoteRuleResult(
                    rule_id=cand.rule.id,
                    status="ineligible",
                    source_version=cand.source_version,
                    reason=e.message,
                )
            )
    results.extend(ineligible)

    promoted = [r for r in results if r.status == "promoted"]
    if promoted:
        await audit_log(
            db, current_user.id, "promotion.applied", "environment",
            str(target_env.id),
            {
                "target_environment_id": str(target_env.id),
                "source_environment_id": str(source_env.id),
                "promoted_rule_ids": [str(r.rule_id) for r in promoted],
                "promoted_count": len(promoted),
                "change_reason": data.change_reason,
            },
            ip_address=get_client_ip(request),
        )
        await db.commit()

    return PromoteResponse(
        target_environment_id=target_env.id,
        source_environment_id=source_env.id,
        deployment_request_id=None,
        results=results,
    )
