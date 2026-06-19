"""Case management API — investigation workspace.

Cases group alerts into an investigation with an owner, status, severity, an
append-only timeline, and comments. Resource-scoped like rules/alerts: admins
see all; others see their team's cases plus global (un-owned) ones. Mutations
require ``manage_alerts``; reads require authentication.
"""

from datetime import UTC
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    get_opensearch_client_optional,
    require_permission_dep,
)
from app.db.session import get_db
from app.models.case import (
    Case,
    CaseAlert,
    CaseComment,
    CaseEvent,
    CaseEventType,
    CaseStatus,
)
from app.models.user import User, UserRole
from app.schemas.case import (
    CASE_STATUSES,
    SEVERITIES,
    CaseAlertAdd,
    CaseAlertResponse,
    CaseAssignRequest,
    CaseCommentCreate,
    CaseCommentResponse,
    CaseCreate,
    CaseDetailResponse,
    CaseEventResponse,
    CaseListResponse,
    CaseResponse,
    CaseStatusUpdate,
    CaseUpdate,
)
from app.services.alerts import AlertService
from app.services.audit import audit_log
from app.services.cases import (
    alert_count,
    apply_close_semantics,
    email_map,
    next_case_number,
    record_event,
)
from app.services.team_scope import apply_team_scope, can_access_resource
from app.utils.request import get_client_ip

router = APIRouter(prefix="/cases", tags=["cases"])

ALERTS_INDEX = "chad-alerts-*"


def _lookup_alert_meta(
    os_client: OpenSearch | None, alert_id: str
) -> tuple[str | None, str | None]:
    """Best-effort fetch of an alert's name + severity from OpenSearch.

    Returns ``(None, None)`` when OpenSearch is unavailable or the alert is
    missing — callers fall back to displaying the raw alert_id.
    """
    if os_client is None:
        return None, None
    alert = AlertService(os_client).get_alert(ALERTS_INDEX, alert_id)
    if not alert:
        return None, None
    title = alert.get("rule_title") or alert.get("title")
    return title, alert.get("severity")


def _case_to_response(case: Case, owner_email: str | None, count: int) -> CaseResponse:
    return CaseResponse(
        id=case.id,
        number=case.number,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        owner_id=case.owner_id,
        owner_email=owner_email,
        team_id=case.team_id,
        created_by=case.created_by,
        sla_due_at=case.sla_due_at,
        sla_breached=case.sla_breached,
        closed_at=case.closed_at,
        tags=case.tags,
        alert_count=count,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


async def _get_case_or_404(db: AsyncSession, case_id: UUID, user: User) -> Case:
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not can_access_resource(case, user):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return case


async def _resolve_owner(db: AsyncSession, user: User, owner_id: UUID | None) -> User | None:
    """Validate an owner assignment is permitted (same team, or actor is admin)."""
    if owner_id is None:
        return None
    owner = (await db.execute(select(User).where(User.id == owner_id))).scalar_one_or_none()
    if owner is None or not owner.is_active:
        raise HTTPException(status_code=404, detail="Owner not found or inactive")
    if user.role != UserRole.ADMIN and owner.team_id != user.team_id:
        raise HTTPException(status_code=403, detail="Owner must be a member of your team")
    return owner


@router.get("", response_model=CaseListResponse)
async def list_cases(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    owner: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = apply_team_scope(select(Case), Case, user)
    if status_filter:
        stmt = stmt.where(Case.status == status_filter)
    if severity:
        stmt = stmt.where(Case.severity == severity)
    if owner == "me":
        stmt = stmt.where(Case.owner_id == user.id)
    elif owner:
        stmt = stmt.where(Case.owner_id == owner)
    if search:
        stmt = stmt.where(Case.title.ilike(f"%{search}%"))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(Case.number.desc()).limit(limit).offset(offset)
    cases = list((await db.execute(stmt)).scalars().all())

    emails = await email_map(db, {c.owner_id for c in cases})
    counts = {}
    if cases:
        rows = (
            await db.execute(
                select(CaseAlert.case_id, func.count(CaseAlert.id))
                .where(CaseAlert.case_id.in_([c.id for c in cases]))
                .group_by(CaseAlert.case_id)
            )
        ).all()
        counts = {row[0]: row[1] for row in rows}

    return CaseListResponse(
        cases=[_case_to_response(c, emails.get(c.owner_id), counts.get(c.id, 0)) for c in cases],
        total=total,
    )


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    data: CaseCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)] = None,
):
    if data.severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(SEVERITIES)}")
    owner = await _resolve_owner(db, user, data.owner_id)

    case = Case(
        number=await next_case_number(db),
        title=data.title,
        description=data.description,
        severity=data.severity,
        status=CaseStatus.OPEN.value,
        owner_id=owner.id if owner else None,
        team_id=user.team_id,
        created_by=user.id,
        tags=data.tags,
    )
    db.add(case)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Case number collision, retry") from None

    record_event(db, case.id, CaseEventType.CREATED, user.id, f"Case created by {user.email}")
    if owner:
        record_event(db, case.id, CaseEventType.ASSIGNED, user.id, f"Assigned to {owner.email}")

    # Seed alerts.
    seeded = {aid for aid in data.alert_ids if aid}
    for aid in seeded:
        title, severity = _lookup_alert_meta(os_client, aid)
        db.add(CaseAlert(
            case_id=case.id, alert_id=aid,
            alert_title=title, alert_severity=severity, added_by=user.id,
        ))
        record_event(
            db, case.id, CaseEventType.ALERT_LINKED, user.id,
            f"Linked alert {aid}", {"alert_id": aid},
        )

    await audit_log(
        db, user.id, "case.create", "case", str(case.id),
        {"number": case.number, "title": case.title}, ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(case)
    owner_email = owner.email if owner else None
    return _case_to_response(case, owner_email, len(seeded))


@router.get("/{case_id}", response_model=CaseDetailResponse)
async def get_case(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)] = None,
):
    case = await _get_case_or_404(db, case_id, user)

    links = list(
        (await db.execute(
            select(CaseAlert).where(CaseAlert.case_id == case_id).order_by(CaseAlert.added_at)
        )).scalars().all()
    )
    events = list(
        (await db.execute(
            select(CaseEvent).where(CaseEvent.case_id == case_id).order_by(CaseEvent.created_at)
        )).scalars().all()
    )
    comments = list(
        (await db.execute(
            select(CaseComment)
            .where(CaseComment.case_id == case_id, CaseComment.deleted_at.is_(None))
            .order_by(CaseComment.created_at)
        )).scalars().all()
    )

    emails = await email_map(
        db,
        {case.owner_id}
        | {e.actor_id for e in events}
        | {c.user_id for c in comments},
    )

    # Lazily backfill alert name/severity for legacy links saved before
    # enrichment (or while OpenSearch was offline). Serialize before commit
    # to respect expire_on_commit.
    dirty = False
    for link in links:
        if link.alert_title is None:
            title, severity = _lookup_alert_meta(os_client, link.alert_id)
            if title is not None:
                link.alert_title = title
                link.alert_severity = severity
                dirty = True
    alert_responses = [CaseAlertResponse.model_validate(link) for link in links]
    if dirty:
        await db.commit()

    base = _case_to_response(case, emails.get(case.owner_id), len(links))
    return CaseDetailResponse(
        **base.model_dump(),
        alerts=alert_responses,
        events=[
            CaseEventResponse(
                id=e.id, event_type=e.event_type, actor_id=e.actor_id,
                actor_email=emails.get(e.actor_id), message=e.message,
                event_metadata=e.event_metadata, created_at=e.created_at,
            )
            for e in events
        ],
        comments=[
            CaseCommentResponse(
                id=c.id, content=c.content, user_id=c.user_id,
                user_email=emails.get(c.user_id), created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in comments
        ],
    )


@router.put("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: UUID,
    data: CaseUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    case = await _get_case_or_404(db, case_id, user)
    if data.title is not None:
        case.title = data.title
    if data.description is not None:
        case.description = data.description
    if data.tags is not None:
        case.tags = data.tags
    if data.severity is not None and data.severity != case.severity:
        if data.severity not in SEVERITIES:
            raise HTTPException(status_code=422, detail="invalid severity")
        old = case.severity
        case.severity = data.severity
        record_event(
            db, case.id, CaseEventType.SEVERITY_CHANGED, user.id,
            f"Severity {old} → {data.severity}",
        )
    await audit_log(
        db, user.id, "case.update", "case", str(case.id), {}, ip_address=get_client_ip(request)
    )
    await db.commit()
    await db.refresh(case)
    emails = await email_map(db, {case.owner_id})
    return _case_to_response(case, emails.get(case.owner_id), await alert_count(db, case.id))


@router.post("/{case_id}/status", response_model=CaseResponse)
async def change_status(
    case_id: UUID,
    data: CaseStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    if data.status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(CASE_STATUSES)}")
    case = await _get_case_or_404(db, case_id, user)
    old = case.status
    if data.status != old:
        case.status = data.status
        apply_close_semantics(case, data.status)
        if data.status == CaseStatus.CLOSED.value:
            evt = CaseEventType.CLOSED
        elif old == CaseStatus.CLOSED.value:
            evt = CaseEventType.REOPENED
        else:
            evt = CaseEventType.STATUS_CHANGED
        msg = f"Status {old} → {data.status}" + (f": {data.note}" if data.note else "")
        record_event(db, case.id, evt, user.id, msg)
    await audit_log(
        db, user.id, "case.status", "case", str(case.id),
        {"status": data.status}, ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(case)
    emails = await email_map(db, {case.owner_id})
    return _case_to_response(case, emails.get(case.owner_id), await alert_count(db, case.id))


@router.post("/{case_id}/assign", response_model=CaseResponse)
async def assign_case(
    case_id: UUID,
    data: CaseAssignRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    case = await _get_case_or_404(db, case_id, user)
    owner = await _resolve_owner(db, user, data.owner_id)
    case.owner_id = owner.id if owner else None
    msg = f"Assigned to {owner.email}" if owner else "Unassigned"
    record_event(db, case.id, CaseEventType.ASSIGNED, user.id, msg)
    await audit_log(
        db, user.id, "case.assign", "case", str(case.id),
        {"owner": owner.email if owner else None}, ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(case)
    return _case_to_response(case, owner.email if owner else None, await alert_count(db, case.id))


@router.post("/{case_id}/alerts", response_model=CaseResponse)
async def add_alerts(
    case_id: UUID,
    data: CaseAlertAdd,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)] = None,
):
    case = await _get_case_or_404(db, case_id, user)
    existing = set(
        (await db.execute(
            select(CaseAlert.alert_id).where(CaseAlert.case_id == case_id)
        )).scalars().all()
    )
    added = 0
    for aid in {a for a in data.alert_ids if a}:
        if aid in existing:
            continue
        title, severity = _lookup_alert_meta(os_client, aid)
        db.add(CaseAlert(
            case_id=case.id, alert_id=aid,
            alert_title=title, alert_severity=severity, added_by=user.id,
        ))
        record_event(
            db, case.id, CaseEventType.ALERT_LINKED, user.id,
            f"Linked alert {aid}", {"alert_id": aid},
        )
        added += 1
    await audit_log(
        db, user.id, "case.alerts_add", "case", str(case.id),
        {"added": added}, ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(case)
    emails = await email_map(db, {case.owner_id})
    return _case_to_response(case, emails.get(case.owner_id), await alert_count(db, case.id))


@router.delete("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_alert(
    case_id: UUID,
    alert_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    case = await _get_case_or_404(db, case_id, user)
    link = (
        await db.execute(
            select(CaseAlert).where(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
        )
    ).scalar_one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail="Alert not linked to this case")
    await db.delete(link)
    record_event(
        db, case.id, CaseEventType.ALERT_UNLINKED, user.id,
        f"Unlinked alert {alert_id}", {"alert_id": alert_id},
    )
    await audit_log(
        db, user.id, "case.alerts_remove", "case", str(case.id),
        {"alert_id": alert_id}, ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/{case_id}/comments", response_model=CaseCommentResponse, status_code=status.HTTP_201_CREATED)
async def add_comment(
    case_id: UUID,
    data: CaseCommentCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    case = await _get_case_or_404(db, case_id, user)
    comment = CaseComment(case_id=case.id, user_id=user.id, content=data.content)
    db.add(comment)
    record_event(db, case.id, CaseEventType.COMMENT, user.id, "Added a comment")
    await db.commit()
    await db.refresh(comment)
    return CaseCommentResponse(
        id=comment.id, content=comment.content, user_id=comment.user_id,
        user_email=user.email, created_at=comment.created_at, updated_at=comment.updated_at,
    )


@router.delete("/{case_id}/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_comment(
    case_id: UUID,
    comment_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    case = await _get_case_or_404(db, case_id, user)
    comment = (
        await db.execute(
            select(CaseComment).where(
                CaseComment.id == comment_id, CaseComment.case_id == case.id
            )
        )
    ).scalar_one_or_none()
    if comment is None or comment.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Comment not found")
    # Only the author or an admin may delete a comment.
    if comment.user_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="You can only delete your own comments")
    from datetime import datetime

    comment.deleted_at = datetime.now(UTC)
    await db.commit()
