"""
System logs API endpoints.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission_dep
from app.db.session import get_db
from app.models.system_log import SystemLog
from app.models.user import User
from app.schemas.system_log import (
    SystemLogEntry,
    SystemLogListResponse,
    SystemLogPurgeResponse,
    SystemLogStatsResponse,
)
from app.services.system_log import system_log_service

router = APIRouter(prefix="/system-logs", tags=["system-logs"])


@router.get("", response_model=SystemLogListResponse)
async def list_system_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_system_logs"))],
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    level: str | None = Query(None, description="Comma-separated: ERROR,WARNING"),
    category: str | None = Query(
        None, description="Comma-separated: opensearch,alerts,pull_mode,integrations,background"
    ),
    search: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Get system logs with optional filters.
    Requires view_system_logs permission.
    """
    levels = [lvl.upper() for lvl in level.split(",")] if level else None
    categories = category.split(",") if category else None

    logs, total = await system_log_service.query_logs(
        db=db,
        start_time=start_time,
        end_time=end_time,
        levels=levels,
        categories=categories,
        search=search,
        limit=limit,
        offset=offset,
    )

    return SystemLogListResponse(
        items=[
            SystemLogEntry(
                id=log.id,
                timestamp=log.timestamp,
                level=log.level,
                category=log.category,
                service=log.service,
                message=log.message,
                details=log.details,
                created_at=log.created_at,
            )
            for log in logs
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=SystemLogStatsResponse)
async def get_system_log_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("view_system_logs"))],
):
    """
    Get system log statistics for last 24 hours.
    Requires view_system_logs permission.
    """
    stats = await system_log_service.get_stats(db)
    return SystemLogStatsResponse(**stats)


@router.delete("", response_model=SystemLogPurgeResponse)
async def purge_system_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
    before: datetime = Query(..., description="Purge logs before this timestamp"),
):
    """
    Manually purge system logs before a given timestamp.
    Requires manage_settings permission (admin only).
    """
    result = await db.execute(
        delete(SystemLog).where(SystemLog.timestamp < before)
    )
    await db.commit()
    return SystemLogPurgeResponse(deleted_count=result.rowcount)
