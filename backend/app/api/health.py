"""Health monitoring endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.ti_config import TISourceConfig
from app.models.user import User
from app.services.health import get_all_indices_health, get_health_history, get_index_health
from app.services.settings import get_setting, set_setting

router = APIRouter(prefix="/health", tags=["health"])

# Default values (same as in health_monitor.py)
DEFAULT_NO_DATA_MINUTES = 15
DEFAULT_ERROR_RATE_PERCENT = 5.0
DEFAULT_LATENCY_MS = 1000
DEFAULT_QUEUE_WARNING = 10000
DEFAULT_QUEUE_CRITICAL = 100000


class HealthSettingsResponse(BaseModel):
    """Response for health settings."""

    no_data_minutes: int
    error_rate_percent: float
    latency_ms: int
    queue_warning: int
    queue_critical: int


class HealthSettingsUpdate(BaseModel):
    """Request for updating health settings."""

    no_data_minutes: int | None = None
    error_rate_percent: float | None = None
    latency_ms: int | None = None
    queue_warning: int | None = None
    queue_critical: int | None = None


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


@router.get("/settings", response_model=HealthSettingsResponse)
async def get_health_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get global health alerting settings."""
    setting = await get_setting(db, "health_thresholds")
    thresholds = setting or {}
    return HealthSettingsResponse(
        no_data_minutes=thresholds.get("no_data_minutes", DEFAULT_NO_DATA_MINUTES),
        error_rate_percent=thresholds.get("error_rate_percent", DEFAULT_ERROR_RATE_PERCENT),
        latency_ms=thresholds.get("latency_ms", DEFAULT_LATENCY_MS),
        queue_warning=thresholds.get("queue_warning", DEFAULT_QUEUE_WARNING),
        queue_critical=thresholds.get("queue_critical", DEFAULT_QUEUE_CRITICAL),
    )


@router.put("/settings", response_model=HealthSettingsResponse)
async def update_health_settings(
    data: HealthSettingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Update global health alerting settings."""
    # Get current settings
    current = await get_setting(db, "health_thresholds")
    thresholds = current or {}

    # Apply updates
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        thresholds[key] = value

    # Save
    await set_setting(db, "health_thresholds", thresholds)

    return HealthSettingsResponse(
        no_data_minutes=thresholds.get("no_data_minutes", DEFAULT_NO_DATA_MINUTES),
        error_rate_percent=thresholds.get("error_rate_percent", DEFAULT_ERROR_RATE_PERCENT),
        latency_ms=thresholds.get("latency_ms", DEFAULT_LATENCY_MS),
        queue_warning=thresholds.get("queue_warning", DEFAULT_QUEUE_WARNING),
        queue_critical=thresholds.get("queue_critical", DEFAULT_QUEUE_CRITICAL),
    )


@router.get("/status")
async def get_health_status(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Get health status of all services."""
    services = []

    # Jira
    result = await db.execute(select(JiraConfig).limit(1))
    jira_config = result.scalar_one_or_none()
    if jira_config and jira_config.is_enabled:
        services.append({
            "service_type": "jira",
            "service_name": "Jira Cloud",
            "status": jira_config.last_health_status or "unknown",
            "last_check": jira_config.last_health_check
        })

    # TI sources
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.is_enabled == True)
    )
    ti_configs = result.scalars().all()
    for config in ti_configs:
        services.append({
            "service_type": config.source_type,
            "service_name": config.source_type.replace("_", " ").title(),
            "status": config.last_health_status or "unknown",
            "last_check": config.last_health_check
        })

    # Get recent health checks for all services
    result = await db.execute(
        select(HealthCheckLog)
        .order_by(HealthCheckLog.checked_at.desc())
        .limit(50)
    )
    recent_checks = result.scalars().all()

    return {
        "services": services,
        "recent_checks": [
            {
                "service_type": c.service_type,
                "service_name": c.service_name,
                "status": c.status,
                "error_message": c.error_message,
                "checked_at": c.checked_at
            }
            for c in recent_checks
        ]
    }


@router.post("/test/{service_type}")
async def test_service_health(
    service_type: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Manually trigger health check for a service."""
    from app.background.tasks.health_checks import check_jira_health, check_opensearch_health

    if service_type == "jira":
        await check_jira_health(db)
        return {"message": "Jira health check triggered"}
    elif service_type == "opensearch":
        await check_opensearch_health(db)
        return {"message": "OpenSearch health check triggered"}

    return {"error": "Unknown service"}, 400
