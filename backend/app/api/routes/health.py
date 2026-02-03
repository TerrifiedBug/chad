"""Health check monitoring endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.ti_config import TISourceConfig
from app.models.user import User

router = APIRouter()


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
        select(TISourceConfig).where(TISourceConfig.is_enabled.is_(True))
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
