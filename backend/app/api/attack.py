"""
ATT&CK Coverage Map API endpoints.
"""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.schemas.attack import (
    CoverageResponse,
    MatrixResponse,
    SyncResponse,
    SyncStatusResponse,
    TechniqueDetailResponse,
)
from app.services.attack_coverage import attack_coverage_service
from app.services.attack_sync import attack_sync_service
from app.services.audit import audit_log
from app.services.scheduler import scheduler_service
from app.utils.request import get_client_ip

router = APIRouter(prefix="/attack", tags=["attack"])


@router.get("/techniques", response_model=MatrixResponse)
async def get_techniques(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Get all techniques grouped by tactic for matrix rendering.

    Returns the full ATT&CK Enterprise Matrix structure.
    """
    return await attack_coverage_service.get_matrix_structure(db)


@router.get("/coverage", response_model=CoverageResponse)
async def get_coverage(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    deployed_only: bool = Query(False, description="Only count deployed rules"),
    severity: list[str] | None = Query(None, description="Filter by severity levels"),
    index_pattern_id: UUID | None = Query(None, description="Filter by index pattern"),
):
    """
    Get coverage counts per technique.

    Returns a dict mapping technique IDs to rule counts.
    """
    return await attack_coverage_service.get_coverage(
        db,
        deployed_only=deployed_only,
        severity=severity,
        index_pattern_id=index_pattern_id,
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueDetailResponse)
async def get_technique(
    technique_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    deployed_only: bool = Query(False),
    severity: list[str] | None = Query(None),
    index_pattern_id: UUID | None = Query(None),
):
    """
    Get technique details with linked rules.

    Returns full technique information including sub-techniques and rules.
    """
    result = await attack_coverage_service.get_technique_detail(
        db,
        technique_id=technique_id,
        deployed_only=deployed_only,
        severity=severity,
        index_pattern_id=index_pattern_id,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technique not found",
        )

    return result


@router.post("/sync", response_model=SyncResponse)
async def sync_attack_data(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Trigger manual ATT&CK data refresh.

    Admin only. Downloads latest STIX data from MITRE and updates the cache.
    """
    result = await attack_sync_service.sync(db)

    # Update last sync time in settings
    setting_result = await db.execute(select(Setting).where(Setting.key == "attack_sync"))
    setting = setting_result.scalar_one_or_none()
    if setting:
        setting.value = {**setting.value, "last_sync": datetime.now(UTC).isoformat()}
    else:
        # Create setting if it doesn't exist
        setting = Setting(
            key="attack_sync",
            value={"last_sync": datetime.now(UTC).isoformat()},
        )
        db.add(setting)

    await db.commit()

    # Audit log
    await audit_log(
        db,
        current_user.id,
        "attack.sync.manual",
        "system",
        None,
        {"success": result.success, "techniques_updated": result.techniques_updated},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return SyncResponse(
        success=result.success,
        message=result.message,
        techniques_updated=result.techniques_updated,
        new_techniques=result.new_techniques,
        error=result.error,
    )


@router.get("/sync/status", response_model=SyncStatusResponse)
async def get_sync_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Get current sync status for settings display.

    Returns last sync time, next scheduled sync, and technique count.
    """
    # Get settings
    result = await db.execute(select(Setting).where(Setting.key == "attack_sync"))
    setting = result.scalar_one_or_none()
    settings_value = setting.value if setting else {}

    # Get technique count
    technique_count = await attack_coverage_service.get_technique_count(db)

    # Get next scheduled run
    next_scheduled = scheduler_service.get_next_run_time("attack_sync")

    # Parse last sync time
    last_sync_str = settings_value.get("last_sync")
    last_sync = None
    if last_sync_str:
        try:
            last_sync = datetime.fromisoformat(last_sync_str.replace("Z", "+00:00"))
        except ValueError:
            pass

    return SyncStatusResponse(
        last_sync=last_sync,
        next_scheduled=next_scheduled,
        sync_enabled=settings_value.get("enabled", False),
        technique_count=technique_count,
        frequency=settings_value.get("frequency"),
    )
