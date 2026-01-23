"""Health monitoring endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.services.health import get_all_indices_health, get_health_history, get_index_health

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/indices")
async def list_index_health(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get health status for all index patterns."""
    return await get_all_indices_health(db)


@router.get("/indices/{index_pattern_id}")
async def get_index_pattern_health(
    index_pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=168),
):
    """Get detailed health for a specific index pattern."""
    return await get_index_health(db, index_pattern_id, hours)


@router.get("/indices/{index_pattern_id}/history")
async def get_index_health_history(
    index_pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=168),
):
    """Get historical metrics for sparkline charts."""
    return await get_health_history(db, index_pattern_id, hours)
