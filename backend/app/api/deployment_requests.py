"""
Dual-control deployment approval API (maker-checker / two-eye).

Lifecycle: a maker with ``deploy_rules`` files a PENDING request (this module);
a different checker with ``approve_deployments`` approves/rejects it (approve and
reject handlers, with the self-review guard + atomic claim). Listing and detail
are team-scoped so reviewers only see their team's requests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_permission_dep
from app.db.session import get_db
from app.models.correlation_rule import CorrelationRule
from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestItem,
    DeploymentRequestKind,
    DeploymentRequestStatus,
)
from app.models.rule import Rule
from app.models.user import User, UserRole
from app.schemas.deployment_request import (
    DeploymentRequestCreate,
    DeploymentRequestDetailResponse,
    DeploymentRequestItemDetail,
    DeploymentRequestResponse,
    DeploymentRequestStats,
)
from app.services.audit import audit_log
from app.services.team_scope import apply_team_scope, can_access_resource
from app.utils.request import get_client_ip

router = APIRouter(prefix="/deployment-requests", tags=["deployment-requests"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _load_request(db: AsyncSession, request_id: UUID) -> DeploymentRequest | None:
    result = await db.execute(
        select(DeploymentRequest)
        .where(DeploymentRequest.id == request_id)
        .options(
            selectinload(DeploymentRequest.items),
            selectinload(DeploymentRequest.requester),
            selectinload(DeploymentRequest.reviewer),
        )
    )
    return result.scalar_one_or_none()


async def _rule_title_map(db: AsyncSession, items: list[DeploymentRequestItem]) -> dict[UUID, str]:
    """Map rule_id / correlation_rule_id -> human title for the given items."""
    rule_ids = [i.rule_id for i in items if i.rule_id is not None]
    corr_ids = [i.correlation_rule_id for i in items if i.correlation_rule_id is not None]
    titles: dict[UUID, str] = {}
    if rule_ids:
        rows = await db.execute(select(Rule.id, Rule.title).where(Rule.id.in_(rule_ids)))
        titles.update({rid: title for rid, title in rows.all()})
    if corr_ids:
        rows = await db.execute(
            select(CorrelationRule.id, CorrelationRule.name).where(CorrelationRule.id.in_(corr_ids))
        )
        titles.update({cid: name for cid, name in rows.all()})
    return titles


def _item_title(item: DeploymentRequestItem, titles: dict[UUID, str]) -> str | None:
    key = item.rule_id or item.correlation_rule_id
    return titles.get(key) if key else None


def _build_summary(
    req: DeploymentRequest, titles: dict[UUID, str], now: datetime
) -> DeploymentRequestResponse:
    return DeploymentRequestResponse(
        id=req.id,
        status=req.status,
        requested_by=req.requested_by,
        requester_email=req.requester.email if req.requester else None,
        reviewed_by=req.reviewed_by,
        reviewer_email=req.reviewer.email if req.reviewer else None,
        change_reason=req.change_reason,
        review_note=req.review_note,
        team_id=req.team_id,
        created_at=req.created_at,
        reviewed_at=req.reviewed_at,
        applied_at=req.applied_at,
        item_count=len(req.items),
        rule_titles=[t for t in (_item_title(i, titles) for i in req.items) if t],
        age_seconds=(now - req.created_at).total_seconds(),
    )


async def _build_detail(
    db: AsyncSession, req: DeploymentRequest, now: datetime
) -> DeploymentRequestDetailResponse:
    titles = await _rule_title_map(db, req.items)
    summary = _build_summary(req, titles, now)

    # Load sigma rules referenced by items (with versions) for the YAML diff.
    sigma_rule_ids = [i.rule_id for i in req.items if i.rule_id is not None]
    rules_by_id: dict[UUID, Rule] = {}
    if sigma_rule_ids:
        rows = await db.execute(
            select(Rule)
            .where(Rule.id.in_(sigma_rule_ids))
            .options(selectinload(Rule.versions))
        )
        rules_by_id = {r.id: r for r in rows.scalars().all()}

    item_details: list[DeploymentRequestItemDetail] = []
    for i in req.items:
        proposed_yaml: str | None = None
        deployed_yaml: str | None = None
        is_stale = False
        rule = rules_by_id.get(i.rule_id) if i.rule_id else None
        if rule is not None:
            current_version = rule.versions[0].version_number if rule.versions else 1
            is_stale = current_version != i.version_number
            # Proposed = the pinned version's YAML (fall back to live content).
            proposed_yaml = next(
                (v.yaml_content for v in rule.versions if v.id == i.rule_version_id),
                rule.yaml_content,
            )
            # Deployed = whatever version is currently live, if any.
            if rule.deployed_version is not None:
                deployed_yaml = next(
                    (v.yaml_content for v in rule.versions if v.version_number == rule.deployed_version),
                    None,
                )
        item_details.append(
            DeploymentRequestItemDetail(
                id=i.id,
                kind=i.kind,
                rule_id=i.rule_id,
                correlation_rule_id=i.correlation_rule_id,
                rule_title=_item_title(i, titles),
                version_number=i.version_number,
                apply_status=i.apply_status,
                apply_error=i.apply_error,
                proposed_yaml=proposed_yaml,
                deployed_yaml=deployed_yaml,
                is_stale=is_stale,
            )
        )

    return DeploymentRequestDetailResponse(
        **summary.model_dump(),
        items=item_details,
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post("", response_model=DeploymentRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_deployment_request(
    data: DeploymentRequestCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """File a PENDING deployment request for one or more rules (maker action).

    Each item pins the rule's current version so a later edit invalidates the
    approval (stale). The requester's team scopes who can review it.
    """
    # Dedupe while preserving the caller's intent.
    unique_ids = list(dict.fromkeys(data.rule_ids))
    rows = await db.execute(
        select(Rule).where(Rule.id.in_(unique_ids)).options(selectinload(Rule.versions))
    )
    rules = {r.id: r for r in rows.scalars().all()}

    missing = [str(rid) for rid in unique_ids if rid not in rules]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rules not found: {', '.join(missing)}",
        )

    for rule in rules.values():
        if not can_access_resource(rule, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to one or more of the selected rules",
            )

    req = DeploymentRequest(
        requested_by=current_user.id,
        change_reason=data.change_reason,
        team_id=current_user.team_id,
        status=DeploymentRequestStatus.PENDING.value,
    )
    for rid in unique_ids:
        rule = rules[rid]
        current_version = rule.versions[0].version_number if rule.versions else 1
        pinned_version_id = rule.versions[0].id if rule.versions else None
        req.items.append(
            DeploymentRequestItem(
                rule_id=rule.id,
                rule_version_id=pinned_version_id,
                version_number=current_version,
                kind=DeploymentRequestKind.SIGMA.value,
            )
        )

    db.add(req)
    await db.flush()

    await audit_log(
        db,
        current_user.id,
        "deployment_request.created",
        "deployment_request",
        str(req.id),
        {
            "rule_ids": [str(rid) for rid in unique_ids],
            "rule_count": len(unique_ids),
            "change_reason": data.change_reason,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    loaded = await _load_request(db, req.id)
    titles = await _rule_title_map(db, loaded.items)
    return _build_summary(loaded, titles, datetime.now(UTC))


@router.get("", response_model=list[DeploymentRequestResponse])
async def list_deployment_requests(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    status_filter: str | None = None,
):
    """List requests visible to the user (team-scoped), newest first.

    Visible to anyone who can act in the flow: ``deploy_rules`` (makers) or
    ``approve_deployments`` (checkers).
    """
    await _require_flow_access(db, current_user)

    stmt = select(DeploymentRequest).options(
        selectinload(DeploymentRequest.items),
        selectinload(DeploymentRequest.requester),
        selectinload(DeploymentRequest.reviewer),
    )
    stmt = apply_team_scope(stmt, DeploymentRequest, current_user)
    if status_filter:
        stmt = stmt.where(DeploymentRequest.status == status_filter)
    stmt = stmt.order_by(DeploymentRequest.created_at.desc())

    result = await db.execute(stmt)
    requests = list(result.scalars().all())

    all_items = [i for r in requests for i in r.items]
    titles = await _rule_title_map(db, all_items)
    now = datetime.now(UTC)
    return [_build_summary(r, titles, now) for r in requests]


@router.get("/stats", response_model=DeploymentRequestStats)
async def deployment_request_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """KPI aggregates for the Approvals hub (team-scoped)."""
    await _require_flow_access(db, current_user)

    stmt = select(
        DeploymentRequest.status,
        DeploymentRequest.created_at,
        DeploymentRequest.reviewed_at,
    )
    stmt = apply_team_scope(stmt, DeploymentRequest, current_user)
    rows = (await db.execute(stmt)).all()

    counts = {s.value: 0 for s in DeploymentRequestStatus}
    review_durations: list[float] = []
    for status_value, created_at, reviewed_at in rows:
        counts[status_value] = counts.get(status_value, 0) + 1
        if reviewed_at is not None and created_at is not None:
            review_durations.append((reviewed_at - created_at).total_seconds())

    avg_review = sum(review_durations) / len(review_durations) if review_durations else None
    return DeploymentRequestStats(
        pending=counts[DeploymentRequestStatus.PENDING.value],
        approved=counts[DeploymentRequestStatus.APPROVED.value],
        applied=counts[DeploymentRequestStatus.APPLIED.value],
        rejected=counts[DeploymentRequestStatus.REJECTED.value],
        cancelled=counts[DeploymentRequestStatus.CANCELLED.value],
        stale=counts[DeploymentRequestStatus.STALE.value],
        failed=counts[DeploymentRequestStatus.FAILED.value],
        avg_review_seconds=avg_review,
    )


@router.get("/{request_id}", response_model=DeploymentRequestDetailResponse)
async def get_deployment_request(
    request_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Request detail with per-item proposed-vs-deployed YAML for the diff."""
    await _require_flow_access(db, current_user)
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    _enforce_team_visibility(req, current_user)
    return await _build_detail(db, req, datetime.now(UTC))


@router.post("/{request_id}/cancel", response_model=DeploymentRequestResponse)
async def cancel_deployment_request(
    request_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Withdraw a PENDING request. Only the original requester may cancel."""
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    if req.requested_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the requester can cancel this request",
        )
    if req.status != DeploymentRequestStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel a request in '{req.status}' state",
        )

    req.status = DeploymentRequestStatus.CANCELLED.value
    await audit_log(
        db,
        current_user.id,
        "deployment_request.cancelled",
        "deployment_request",
        str(req.id),
        {"rule_count": len(req.items)},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    loaded = await _load_request(db, req.id)
    titles = await _rule_title_map(db, loaded.items)
    return _build_summary(loaded, titles, datetime.now(UTC))


# --------------------------------------------------------------------------- #
# Access helpers
# --------------------------------------------------------------------------- #
async def _require_flow_access(db: AsyncSession, user: User) -> None:
    """Allow users who can act in the approval flow (maker or checker)."""
    from app.services.permissions import has_permission

    if await has_permission(db, user, "deploy_rules") or await has_permission(
        db, user, "approve_deployments"
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Permission required: deploy_rules or approve_deployments",
    )


def _enforce_team_visibility(req: DeploymentRequest, user: User) -> None:
    """Non-admins may only see their own team's (or global) requests."""
    if user.role == UserRole.ADMIN:
        return
    if req.team_id is not None and req.team_id != user.team_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
