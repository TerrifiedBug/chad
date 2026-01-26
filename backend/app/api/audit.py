import csv
import json
from datetime import datetime
from io import StringIO
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_permission_dep, get_current_user
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogEntry, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])


class AccessDeniedLog(BaseModel):
    """Schema for logging access denied events."""
    action: str = "route_access_denied"
    details: dict


@router.post("/log")
async def log_access_denied(
    log_data: AccessDeniedLog,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User | None, Depends(get_current_user)],
):
    """
    Log access denied event to audit log.

    Called by frontend when user attempts to access a route without permission.
    """
    # Create audit log entry
    log = AuditLog(
        user_id=current_user.id if current_user else None,
        action=log_data.action,
        resource_type="route",
        details=log_data.details,
    )
    db.add(log)
    await db.commit()

    return {"success": True}


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_audit"))],
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
                ip_address=log.ip_address,
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
    _: Annotated[User, Depends(require_permission_dep("view_audit"))],
):
    """Get list of distinct action types for filtering."""
    result = await db.execute(select(AuditLog.action).distinct())
    actions = [row[0] for row in result.all()]
    return {"actions": sorted(actions)}


@router.get("/resource-types")
async def list_resource_types(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_audit"))],
):
    """Get list of distinct resource types for filtering."""
    result = await db.execute(select(AuditLog.resource_type).distinct())
    types = [row[0] for row in result.all()]
    return {"resource_types": sorted(types)}


@router.get("/export")
async def export_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_audit"))],
    format: str = Query("csv", pattern="^(csv|json)$"),
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
):
    """Export audit logs in CSV or JSON format."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    result = await db.execute(query)
    logs = result.scalars().all()

    # Get user emails for display
    user_ids = {log.user_id for log in logs if log.user_id}
    users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users = {str(u.id): u.email for u in users_result.scalars().all()}

    if format == "json":
        data = []
        for log in logs:
            user_email = users.get(str(log.user_id)) if log.user_id else None
            if not user_email and log.details:
                user_email = log.details.get("user_email") or log.details.get("email")
            data.append({
                "id": str(log.id),
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "user_email": user_email,
                "ip_address": log.ip_address,
                "details": log.details,
                "created_at": log.created_at.isoformat(),
            })
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_logs.json"},
        )
    else:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["ID", "Action", "Resource Type", "Resource ID", "User", "IP", "Details", "Created At"]
        )
        for log in logs:
            user_email = users.get(str(log.user_id)) if log.user_id else None
            if not user_email and log.details:
                user_email = log.details.get("user_email") or log.details.get("email")
            writer.writerow([
                str(log.id),
                log.action,
                log.resource_type,
                str(log.resource_id) if log.resource_id else "",
                user_email or "",
                log.ip_address or "",
                json.dumps(log.details) if log.details else "",
                log.created_at.isoformat(),
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )
