"""Scheduled reporting API (F5) — admin only.

Manage recurring detection/compliance reports, preview a report on demand, and
run/deliver one immediately. Webhook delivery URLs are SSRF-validated; the auth
header value is encrypted at rest and never returned.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client_optional, require_admin
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.report_schedule import ReportSchedule
from app.models.user import User
from app.schemas.report_schedule import (
    CADENCES,
    FRAMEWORKS,
    REPORT_TYPES,
    ReportScheduleCreate,
    ReportScheduleResponse,
    ReportScheduleUpdate,
)
from app.services.audit import audit_log
from app.services.reporting import build_report, compute_next_run, deliver_report
from app.services.webhooks import _validate_url_components
from app.utils.request import get_client_ip

router = APIRouter(prefix="/report-schedules", tags=["report-schedules"])


def _validate(report_type: str, cadence: str, framework: str | None, delivery_target: str | None) -> None:
    if report_type not in REPORT_TYPES:
        raise HTTPException(422, f"report_type must be one of {sorted(REPORT_TYPES)}")
    if cadence not in CADENCES:
        raise HTTPException(422, f"cadence must be one of {sorted(CADENCES)}")
    if report_type == "compliance" and framework not in FRAMEWORKS:
        raise HTTPException(422, f"compliance reports require framework in {sorted(FRAMEWORKS)}")
    if delivery_target:
        ok, err, _ = _validate_url_components(delivery_target)
        if not ok:
            raise HTTPException(422, f"Invalid delivery URL: {err}")


async def _get_or_404(db: AsyncSession, schedule_id: UUID) -> ReportSchedule:
    s = (await db.execute(select(ReportSchedule).where(ReportSchedule.id == schedule_id))).scalar_one_or_none()
    if s is None:
        raise HTTPException(404, "Report schedule not found")
    return s


@router.get("/preview")
async def preview_report(
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client=Depends(get_opensearch_client_optional),
    _: Annotated[User, Depends(get_current_user)] = None,
    report_type: Annotated[str, Query()] = "coverage",
    framework: Annotated[str | None, Query()] = None,
):
    """Build a report on demand (no delivery) — for the UI preview."""
    _validate(report_type, "weekly", framework, None)
    try:
        return await build_report(db, os_client, report_type, framework)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@router.get("", response_model=list[ReportScheduleResponse])
async def list_schedules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    rows = await db.execute(select(ReportSchedule).order_by(ReportSchedule.name))
    return list(rows.scalars().all())


@router.post("", response_model=ReportScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    data: ReportScheduleCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    _validate(data.report_type, data.cadence, data.framework, data.delivery_target)
    now = datetime.now(UTC)
    schedule = ReportSchedule(
        name=data.name,
        report_type=data.report_type,
        cadence=data.cadence,
        framework=data.framework,
        delivery_type=data.delivery_type,
        delivery_target=data.delivery_target,
        delivery_header_name=data.delivery_header_name,
        delivery_header_value=encrypt(data.delivery_header_value) if data.delivery_header_value else None,
        enabled=data.enabled,
        created_by=admin.id,
        team_id=admin.team_id,
        organization_id=admin.organization_id,
        next_run_at=compute_next_run(now, data.cadence),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    await audit_log(
        db, admin.id, "report_schedule.create", "report_schedule", str(schedule.id),
        {"name": schedule.name, "type": schedule.report_type}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return schedule


@router.put("/{schedule_id}", response_model=ReportScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    data: ReportScheduleUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    s = await _get_or_404(db, schedule_id)
    if data.name is not None:
        s.name = data.name
    if data.cadence is not None:
        if data.cadence not in CADENCES:
            raise HTTPException(422, "invalid cadence")
        s.cadence = data.cadence
        s.next_run_at = compute_next_run(datetime.now(UTC), data.cadence)
    if data.framework is not None:
        s.framework = data.framework
    if data.delivery_target is not None:
        if data.delivery_target:
            ok, err, _ = _validate_url_components(data.delivery_target)
            if not ok:
                raise HTTPException(422, f"Invalid delivery URL: {err}")
        s.delivery_target = data.delivery_target
    if data.delivery_header_name is not None:
        s.delivery_header_name = data.delivery_header_name
    if data.delivery_header_value:
        s.delivery_header_value = encrypt(data.delivery_header_value)
    if data.enabled is not None:
        s.enabled = data.enabled
    await db.commit()
    await db.refresh(s)
    await audit_log(
        db, admin.id, "report_schedule.update", "report_schedule", str(s.id), {},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return s


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    s = await _get_or_404(db, schedule_id)
    await db.delete(s)
    await audit_log(
        db, admin.id, "report_schedule.delete", "report_schedule", str(schedule_id),
        {"name": s.name}, ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
    os_client=Depends(get_opensearch_client_optional),
):
    """Build and deliver a schedule's report immediately; report the outcome."""
    s = await _get_or_404(db, schedule_id)
    try:
        report = await build_report(db, os_client, s.report_type, s.framework)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    delivered = await deliver_report(s, report, decrypt_header=decrypt)
    s.last_run_at = datetime.now(UTC)
    await db.commit()
    return {"delivered": delivered, "report": report}
