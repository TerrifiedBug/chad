from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogEntry, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
    user_id: str | None = Query(None),
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Get audit log entries with optional filters.
    Admin only. Returns paginated list of audit events.
    """
    # Build query with filters
    query = select(AuditLog)

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    # Get user emails for display
    user_ids = {log.user_id for log in logs if log.user_id}
    users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users = {str(u.id): u.email for u in users_result.scalars().all()}

    items = []
    for log in logs:
        # Get user email from user lookup, or fall back to details.user_email (for system events)
        user_email = users.get(str(log.user_id)) if log.user_id else None
        if not user_email and log.details:
            user_email = log.details.get("user_email") or log.details.get("email")
        items.append(
            AuditLogEntry(
                id=log.id,
                user_id=log.user_id,
                user_email=user_email,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                details=log.details,
                created_at=log.created_at,
            )
        )

    return AuditLogListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/actions")
async def list_audit_actions(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get list of distinct action types for filtering."""
    result = await db.execute(select(AuditLog.action).distinct())
    actions = [row[0] for row in result.all()]
    return {"actions": sorted(actions)}


@router.get("/resource-types")
async def list_resource_types(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get list of distinct resource types for filtering."""
    result = await db.execute(select(AuditLog.resource_type).distinct())
    types = [row[0] for row in result.all()]
    return {"resource_types": sorted(types)}
