"""
Dual-control deployment approval API (maker-checker / two-eye).

Lifecycle: a maker with ``deploy_rules`` files a PENDING request (this module);
a different checker with ``approve_deployments`` approves/rejects it (approve and
reject handlers, with the self-review guard + atomic claim). Listing and detail
are team-scoped so reviewers only see their team's requests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_opensearch_client, require_permission_dep
from app.db.session import get_db
from app.models.correlation_rule import CorrelationRule
from app.models.deployment_request import (
    DeploymentItemApplyStatus,
    DeploymentRequest,
    DeploymentRequestApproval,
    DeploymentRequestItem,
    DeploymentRequestKind,
    DeploymentRequestStatus,
)
from app.models.environment import Environment
from app.models.rule import Rule
from app.models.user import User, UserRole
from app.schemas.deployment_request import (
    DeploymentRequestApprovalInfo,
    DeploymentRequestCreate,
    DeploymentRequestDetailResponse,
    DeploymentRequestItemDetail,
    DeploymentRequestReject,
    DeploymentRequestResponse,
    DeploymentRequestStats,
)
from app.services.audit import audit_log
from app.services.deployment import (
    DeploymentApplyError,
    apply_correlation_rule_deployment,
    apply_sigma_rule_deployment,
    create_deployment_request,
)
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
            selectinload(DeploymentRequest.approvals).selectinload(
                DeploymentRequestApproval.approver
            ),
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


async def _approval_deadline(db: AsyncSession) -> datetime | None:
    """Compute the approval SLA deadline from the configured horizon (hours).

    Setting key ``deploy_approval_sla_hours`` (int); 0 / unset = no deadline.
    """
    from app.services.settings import get_setting

    cfg = await get_setting(db, "deploy_approval_sla_hours")
    hours = 0
    if isinstance(cfg, dict):
        try:
            hours = int(cfg.get("hours", 0))
        except (TypeError, ValueError):
            hours = 0
    if hours <= 0:
        return None
    return datetime.now(UTC) + timedelta(hours=hours)


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
        required_approvals=req.required_approvals,
        approvals_count=len(req.approvals),
        approval_deadline=req.approval_deadline,
        is_overdue=(
            req.status == DeploymentRequestStatus.PENDING.value
            and req.approval_deadline is not None
            and now > req.approval_deadline
        ),
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
        approvals=[
            DeploymentRequestApprovalInfo(
                approver_id=a.approver_id,
                approver_email=a.approver.email if a.approver else None,
                note=a.note,
                created_at=a.created_at,
            )
            for a in sorted(req.approvals, key=lambda a: a.created_at)
        ],
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post("", response_model=DeploymentRequestResponse, status_code=status.HTTP_201_CREATED)
async def file_deployment_request(
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

    req = await create_deployment_request(
        db,
        requested_by=current_user.id,
        team_id=current_user.team_id,
        change_reason=data.change_reason,
        sigma_rules=[rules[rid] for rid in unique_ids],
        required_approvals=data.required_approvals or 1,
        approval_deadline=await _approval_deadline(db),
    )

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
        # _build_summary reads len(req.approvals); eager-load it or the async
        # session lazy-loads in the response builder and 500s.
        selectinload(DeploymentRequest.approvals),
    )
    stmt = apply_team_scope(stmt, DeploymentRequest, current_user)
    if status_filter:
        if status_filter not in {s.value for s in DeploymentRequestStatus}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid status filter: {status_filter}",
            )
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


@router.post("/{request_id}/approve", response_model=DeploymentRequestDetailResponse)
async def approve_deployment_request(
    request_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("approve_deployments"))],
):
    """Approve and apply a PENDING request (checker action).

    Enforces, in order: still-pending, team visibility, self-review guard
    (requester != approver), all-or-nothing stale pre-check, then a race-safe
    atomic claim. Only after the claim succeeds does it apply each item via the
    shared deploy service in the approver's request context.
    """
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    _enforce_team_visibility(req, current_user)
    if req.status != DeploymentRequestStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request is not pending (current state: '{req.status}')",
        )
    # Self-review guard: a maker cannot also be the checker. Admins are exempt
    # so a single-admin deployment isn't permanently blocked — dual-control still
    # applies to non-admin makers (analysts still need a separate approver).
    if req.requested_by == current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot approve your own deployment request",
        )

    # --- Multi-approver quorum (I3) -------------------------------------------
    # Record this checker's approval (idempotent per user). When the recorded
    # approvals are still short of required_approvals, the request stays PENDING
    # and we return the updated progress without applying. The final approver
    # (count == required) falls through to the existing stale-check + atomic
    # claim + apply path, so the apply remains single-writer and race-safe.
    if any(a.approver_id == current_user.id for a in req.approvals):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You have already approved this request",
        )
    db.add(DeploymentRequestApproval(request_id=req.id, approver_id=current_user.id))
    await db.commit()
    await audit_log(
        db, current_user.id, "deployment_request.approval_recorded", "deployment_request",
        str(request_id), {}, ip_address=get_client_ip(request),
    )
    await db.commit()

    # Expire just this request so the reload truly refetches the new approval
    # (sessions configured with expire_on_commit=False otherwise return the
    # stale, already-loaded approvals collection). Scoped to ``req`` so we don't
    # disturb other identity-mapped objects.
    db.expire(req)
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    if len(req.approvals) < req.required_approvals:
        # Quorum not yet met — leave PENDING and report progress.
        return await _build_detail(db, req, datetime.now(UTC))

    # All-or-nothing stale pre-check: if any pinned rule changed, apply nothing.
    if await _detect_stale(db, req):
        marked = await db.execute(
            update(DeploymentRequest)
            .where(
                DeploymentRequest.id == request_id,
                DeploymentRequest.status == DeploymentRequestStatus.PENDING.value,
            )
            .values(
                status=DeploymentRequestStatus.STALE.value,
                reviewed_by=current_user.id,
                reviewed_at=datetime.now(UTC),
            )
        )
        await db.commit()
        if marked.rowcount:
            await audit_log(
                db, current_user.id, "deployment_request.stale", "deployment_request",
                str(request_id), {"reason": "a pinned rule changed since the request was filed"},
                ip_address=get_client_ip(request),
            )
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="One or more rules changed since this request was filed; it is now stale. "
            "Ask the requester to re-submit.",
        )

    # Atomic claim: first writer wins; concurrent approvers get rowcount 0.
    now = datetime.now(UTC)
    claim = await db.execute(
        update(DeploymentRequest)
        .where(
            DeploymentRequest.id == request_id,
            DeploymentRequest.status == DeploymentRequestStatus.PENDING.value,
        )
        .values(
            status=DeploymentRequestStatus.APPROVED.value,
            reviewed_by=current_user.id,
            reviewed_at=now,
        )
    )
    await db.commit()
    if claim.rowcount == 0:
        fresh = await _load_request(db, request_id)
        current = fresh.status if fresh else "gone"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request was already handled by another reviewer (now '{current}')",
        )
    await audit_log(
        db, current_user.id, "deployment_request.approved", "deployment_request",
        str(request_id), {"rule_count": len(req.items)}, ip_address=get_client_ip(request),
    )
    await db.commit()

    # Apply each item independently; record per-item outcome (partial failures
    # are reported, not rolled back — percolator writes are independent).
    req = await _load_request(db, request_id)
    ip = get_client_ip(request)
    sigma_rules, corr_rules = await _load_apply_targets(db, req)

    # Per-env dual-control: a promotion request carries the target env. Resolve it
    # once and apply each item INTO that env (target percolator namespace +
    # binding). When null (existing deploy requests) the env is None == the
    # legacy default env, so behavior is unchanged.
    target_env: Environment | None = None
    if req.target_environment_id is not None:
        target_env = (
            await db.execute(
                select(Environment).where(Environment.id == req.target_environment_id)
            )
        ).scalar_one_or_none()
        # The request targeted a specific env that has since been deleted. Do NOT
        # silently fall back to the default env (that would promote to prod's
        # default instead of the intended target). Mark FAILED and abort.
        if target_env is None:
            req.status = DeploymentRequestStatus.FAILED.value
            await db.commit()
            await audit_log(
                db, current_user.id, "deployment_request.failed", "deployment_request",
                str(request_id),
                {"reason": "target environment for this request no longer exists",
                 "target_environment_id": str(req.target_environment_id)},
                ip_address=ip,
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Target environment for this request no longer exists",
            )

    all_ok = True
    for item in req.items:
        try:
            if item.kind == DeploymentRequestKind.CORRELATION.value:
                corr = corr_rules.get(item.correlation_rule_id)
                if corr is None:
                    raise DeploymentApplyError("Correlation rule no longer exists", kind="missing")
                await apply_correlation_rule_deployment(
                    db, corr, actor_id=current_user.id, change_reason=req.change_reason,
                    request_ip=ip, deployment_request_id=req.id,
                )
            else:
                rule = sigma_rules.get(item.rule_id)
                if rule is None:
                    raise DeploymentApplyError("Rule no longer exists", kind="missing")
                # Deploy the exact reviewed version (pinned), not live content,
                # so what the checker approved is what reaches the percolator.
                pinned = next(
                    (v for v in rule.versions if v.id == item.rule_version_id), None
                )
                await apply_sigma_rule_deployment(
                    db, os_client, rule, actor_id=current_user.id, change_reason=req.change_reason,
                    request_ip=ip, deployment_request_id=req.id,
                    pinned_yaml=pinned.yaml_content if pinned else None,
                    pinned_version=item.version_number,
                    environment=target_env,
                )
            item.apply_status = DeploymentItemApplyStatus.OK.value
            item.apply_error = None
        except Exception as e:  # noqa: BLE001 - per-item isolation; recorded below
            item.apply_status = DeploymentItemApplyStatus.FAILED.value
            item.apply_error = str(e)
            all_ok = False

    req.status = (
        DeploymentRequestStatus.APPLIED.value if all_ok else DeploymentRequestStatus.FAILED.value
    )
    if all_ok:
        req.applied_at = datetime.now(UTC)
    await db.commit()

    await audit_log(
        db, current_user.id,
        "deployment_request.applied" if all_ok else "deployment_request.failed",
        "deployment_request", str(req.id),
        {
            "all_ok": all_ok,
            "target_environment_id": (
                str(req.target_environment_id) if req.target_environment_id else None
            ),
            "items": [
                {
                    "rule_id": str(i.rule_id or i.correlation_rule_id),
                    "kind": i.kind,
                    "apply_status": i.apply_status,
                    "apply_error": i.apply_error,
                }
                for i in req.items
            ],
        },
        ip_address=ip,
    )
    # A promotion request (target env set) that applied also emits promotion.applied
    # so the promotion audit trail is symmetric with promotion.requested.
    if all_ok and req.target_environment_id is not None:
        await audit_log(
            db, current_user.id, "promotion.applied", "environment",
            str(req.target_environment_id),
            {
                "target_environment_id": str(req.target_environment_id),
                "deployment_request_id": str(req.id),
                "promoted_rule_ids": [str(i.rule_id) for i in req.items if i.rule_id],
                "promoted_count": len(req.items),
            },
            ip_address=ip,
        )
    await db.commit()

    return await _build_detail(db, await _load_request(db, request_id), datetime.now(UTC))


@router.post("/{request_id}/reject", response_model=DeploymentRequestDetailResponse)
async def reject_deployment_request(
    request_id: UUID,
    body: DeploymentRequestReject,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("approve_deployments"))],
):
    """Reject a PENDING request with a required note (checker action)."""
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    _enforce_team_visibility(req, current_user)
    if req.status != DeploymentRequestStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request is not pending (current state: '{req.status}')",
        )
    if req.requested_by == current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot reject your own deployment request",
        )

    now = datetime.now(UTC)
    claim = await db.execute(
        update(DeploymentRequest)
        .where(
            DeploymentRequest.id == request_id,
            DeploymentRequest.status == DeploymentRequestStatus.PENDING.value,
        )
        .values(
            status=DeploymentRequestStatus.REJECTED.value,
            reviewed_by=current_user.id,
            reviewed_at=now,
            review_note=body.review_note,
        )
    )
    await db.commit()
    if claim.rowcount == 0:
        fresh = await _load_request(db, request_id)
        current = fresh.status if fresh else "gone"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Request was already handled by another reviewer (now '{current}')",
        )
    await audit_log(
        db, current_user.id, "deployment_request.rejected", "deployment_request",
        str(request_id), {"review_note": body.review_note}, ip_address=get_client_ip(request),
    )
    await db.commit()

    return await _build_detail(db, await _load_request(db, request_id), datetime.now(UTC))


# Terminal states a requester can re-file from without re-selecting rules.
_RESUBMITTABLE = frozenset(
    {
        DeploymentRequestStatus.REJECTED.value,
        DeploymentRequestStatus.STALE.value,
        DeploymentRequestStatus.CANCELLED.value,
    }
)


@router.post("/{request_id}/resubmit", response_model=DeploymentRequestResponse,
             status_code=status.HTTP_201_CREATED)
async def resubmit_deployment_request(
    request_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Re-file a fresh PENDING request from a rejected/stale/cancelled one.

    Re-pins the same rules at their *current* versions (so a stale request picks
    up the edits that invalidated it) instead of forcing the maker to re-select
    every rule. Approvals start over.
    """
    req = await _load_request(db, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    _enforce_team_visibility(req, current_user)
    if req.status not in _RESUBMITTABLE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only rejected/stale/cancelled requests can be resubmitted (current: '{req.status}')",
        )

    sigma_ids = [i.rule_id for i in req.items if i.rule_id is not None]
    corr_ids = [i.correlation_rule_id for i in req.items if i.correlation_rule_id is not None]
    if not sigma_ids and not corr_ids:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nothing to resubmit")

    sigma_rules: list[Rule] = []
    if sigma_ids:
        rows = await db.execute(
            select(Rule).where(Rule.id.in_(sigma_ids)).options(selectinload(Rule.versions))
        )
        sigma_rules = list(rows.scalars().all())
        for rule in sigma_rules:
            if not can_access_resource(rule, current_user):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to a rule")

    correlation_rules: list[CorrelationRule] = []
    if corr_ids:
        rows = await db.execute(select(CorrelationRule).where(CorrelationRule.id.in_(corr_ids)))
        correlation_rules = list(rows.scalars().all())

    new_req = await create_deployment_request(
        db,
        requested_by=current_user.id,
        team_id=current_user.team_id,
        change_reason=f"Resubmit of request {req.id}: {req.change_reason}",
        sigma_rules=sigma_rules,
        correlation_rules=correlation_rules,
        required_approvals=req.required_approvals,
        approval_deadline=await _approval_deadline(db),
    )
    await audit_log(
        db, current_user.id, "deployment_request.resubmitted", "deployment_request",
        str(new_req.id), {"resubmit_of": str(req.id)}, ip_address=get_client_ip(request),
    )
    await db.commit()

    loaded = await _load_request(db, new_req.id)
    titles = await _rule_title_map(db, loaded.items)
    return _build_summary(loaded, titles, datetime.now(UTC))


# --------------------------------------------------------------------------- #
# Apply / stale helpers
# --------------------------------------------------------------------------- #
async def _detect_stale(db: AsyncSession, req: DeploymentRequest) -> bool:
    """Whether any item's pinned version differs from the rule's current version."""
    sigma_ids = [i.rule_id for i in req.items if i.rule_id is not None]
    corr_ids = [i.correlation_rule_id for i in req.items if i.correlation_rule_id is not None]

    sigma_current: dict[UUID, int] = {}
    if sigma_ids:
        rows = await db.execute(
            select(Rule).where(Rule.id.in_(sigma_ids)).options(selectinload(Rule.versions))
        )
        for r in rows.scalars().all():
            sigma_current[r.id] = r.versions[0].version_number if r.versions else 1

    corr_current: dict[UUID, int] = {}
    if corr_ids:
        rows = await db.execute(
            select(CorrelationRule.id, CorrelationRule.current_version).where(
                CorrelationRule.id.in_(corr_ids)
            )
        )
        corr_current = {cid: cv for cid, cv in rows.all()}

    for i in req.items:
        if i.rule_id is not None and sigma_current.get(i.rule_id) != i.version_number:
            return True
        if i.correlation_rule_id is not None and corr_current.get(i.correlation_rule_id) != i.version_number:
            return True
    return False


async def _load_apply_targets(
    db: AsyncSession, req: DeploymentRequest
) -> tuple[dict[UUID, Rule], dict[UUID, CorrelationRule]]:
    """Load the sigma rules (with index_pattern + versions) and correlation rules to apply."""
    sigma_ids = [i.rule_id for i in req.items if i.rule_id is not None]
    corr_ids = [i.correlation_rule_id for i in req.items if i.correlation_rule_id is not None]

    sigma_rules: dict[UUID, Rule] = {}
    if sigma_ids:
        rows = await db.execute(
            select(Rule)
            .where(Rule.id.in_(sigma_ids))
            .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
        )
        sigma_rules = {r.id: r for r in rows.scalars().all()}

    corr_rules: dict[UUID, CorrelationRule] = {}
    if corr_ids:
        rows = await db.execute(select(CorrelationRule).where(CorrelationRule.id.in_(corr_ids)))
        corr_rules = {c.id: c for c in rows.scalars().all()}

    return sigma_rules, corr_rules


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
