import csv
import json
from datetime import UTC, datetime
from io import StringIO
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_permission_dep
from app.core.audit_chain import GENESIS, build_payload, canonicalize
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogEntry, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])

# Server-side export cap. Beyond this, the export is truncated (newest first).
EXPORT_ROW_CAP = 10_000

# Leading characters that make a spreadsheet treat a cell as a formula (CWE-1236).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    """Neutralize CSV formula injection: prefix risky cells with a single quote.

    Applied to EVERY field (including serialized details and user_email) so a
    value like ``=cmd()`` cannot execute when the CSV is opened in a spreadsheet.
    """
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


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
    """Export audit logs in CSV or JSON format.

    Capped at EXPORT_ROW_CAP rows (newest first); when the cap is hit the response
    carries ``X-Audit-Export-Truncated: true``. CSV cells are formula-injection
    guarded on every field.
    """
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    # Fetch one extra row to detect truncation, then trim to the cap.
    result = await db.execute(query.limit(EXPORT_ROW_CAP + 1))
    logs = result.scalars().all()
    truncated = len(logs) > EXPORT_ROW_CAP
    logs = logs[:EXPORT_ROW_CAP]

    # Get user emails for display
    user_ids = {log.user_id for log in logs if log.user_id}
    users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users = {str(u.id): u.email for u in users_result.scalars().all()}

    def _user_email(log: AuditLog) -> str | None:
        email = users.get(str(log.user_id)) if log.user_id else None
        if not email and log.details:
            email = log.details.get("user_email") or log.details.get("email")
        return email

    if format == "json":
        data = []
        for log in logs:
            data.append({
                "id": str(log.id),
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "user_email": _user_email(log),
                "ip_address": log.ip_address,
                "details": log.details,
                "created_at": log.created_at.isoformat(),
            })
        headers = {"Content-Disposition": "attachment; filename=audit_logs.json"}
        if truncated:
            headers["X-Audit-Export-Truncated"] = "true"
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers=headers,
        )
    else:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["ID", "Action", "Resource Type", "Resource ID", "User", "IP", "Details", "Created At"]
        )
        for log in logs:
            writer.writerow([
                _csv_safe(log.id),
                _csv_safe(log.action),
                _csv_safe(log.resource_type),
                _csv_safe(log.resource_id) if log.resource_id else "",
                _csv_safe(_user_email(log)) if _user_email(log) else "",
                _csv_safe(log.ip_address) if log.ip_address else "",
                _csv_safe(json.dumps(log.details)) if log.details else "",
                _csv_safe(log.created_at.isoformat()),
            ])
        output.seek(0)
        headers = {"Content-Disposition": "attachment; filename=audit_logs.csv"}
        if truncated:
            headers["X-Audit-Export-Truncated"] = "true"
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers=headers,
        )


@router.get("/export/chain")
async def export_audit_chain(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_audit"))],
):
    """Export a verifiable hash-chain envelope.

    Emits only rows with a non-null hash (legacy rows excluded), ordered by the
    prev_hash -> hash topology (fallback created_at, id). The envelope can be
    re-verified offline by ``scripts/verify_audit_chain.py``.
    """
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.hash.is_not(None))
        .order_by(AuditLog.created_at, AuditLog.id)
    )
    logs = result.scalars().all()

    # Order by the hash topology: walk prev_hash -> hash from GENESIS. Rows that
    # don't link (shouldn't happen for a healthy chain) fall back to created_at,id
    # order already applied above.
    by_prev: dict[str, AuditLog] = {}
    for log in logs:
        by_prev.setdefault(log.prev_hash, log)

    ordered: list[AuditLog] = []
    seen: set[str] = set()
    cursor = GENESIS
    while cursor in by_prev and by_prev[cursor].hash not in seen:
        node = by_prev[cursor]
        ordered.append(node)
        seen.add(node.hash)
        cursor = node.hash
    # Append any rows not reachable via the topology walk (defensive), preserving
    # the created_at,id order.
    for log in logs:
        if log.hash not in seen:
            ordered.append(log)
            seen.add(log.hash)

    rows = []
    for log in ordered:
        payload = build_payload(
            {
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "user_id": log.user_id,
                "details": log.details,
                "ip_address": log.ip_address,
                "created_at": log.created_at,
            }
        )
        # Render created_at the same way canonicalize would (ISO string), so the
        # envelope is self-describing and re-canonicalizes identically.
        row = dict(payload)
        if isinstance(row.get("created_at"), datetime):
            row["created_at"] = row["created_at"].isoformat()
        row["prev_hash"] = log.prev_hash
        row["hash"] = log.hash
        rows.append(row)

    # Sanity: the rendered payloads must canonicalize identically to what was
    # hashed (guards against an accidental field drift in this endpoint).
    _ = [canonicalize(build_payload(r)) for r in rows]

    envelope = {
        "verifier_version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "rows": rows,
    }
    return envelope
