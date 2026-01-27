"""Health monitoring endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_opensearch_client, require_admin
from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.setting import Setting
from app.models.ti_config import TISourceConfig
from app.models.user import User
from app.services.health import get_all_indices_health, get_health_history, get_index_health
from app.services.settings import get_setting, set_setting
from opensearchpy import OpenSearch

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
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get health status for all index patterns."""
    return await get_all_indices_health(db, os_client)


@router.get("/indices/{index_pattern_id}")
async def get_index_pattern_health(
    index_pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=168),
):
    """Get detailed health for a specific index pattern."""
    return await get_index_health(db, os_client, index_pattern_id, hours)


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


# Health Check Interval Configuration
class HealthIntervalConfig(BaseModel):
    """Health check interval configuration."""

    jira_interval_seconds: int = Field(ge=60, le=3600, default=900, description="Jira health check interval (15 min default)")
    sigmahq_interval_seconds: int = Field(ge=60, le=3600, default=3600, description="SigmaHQ health check interval (60 min default)")
    mitre_attack_interval_seconds: int = Field(ge=60, le=3600, default=3600, description="MITRE ATT&CK health check interval (60 min default)")
    opensearch_interval_seconds: int = Field(ge=30, le=600, default=300, description="OpenSearch health check interval (5 min default)")
    ti_interval_seconds: int = Field(ge=60, le=3600, default=1800, description="TI sources health check interval (30 min default)")


class HealthIntervalResponse(BaseModel):
    """Response for health interval settings."""

    jira_interval_seconds: int
    sigmahq_interval_seconds: int
    mitre_attack_interval_seconds: int
    opensearch_interval_seconds: int
    ti_interval_seconds: int


@router.get("/intervals", response_model=HealthIntervalResponse)
async def get_health_intervals(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get health check interval configuration."""
    setting = await get_setting(db, "health_check_intervals")
    intervals = setting or {}

    return HealthIntervalResponse(
        jira_interval_seconds=intervals.get("jira_interval_seconds", 900),
        sigmahq_interval_seconds=intervals.get("sigmahq_interval_seconds", 3600),
        mitre_attack_interval_seconds=intervals.get("mitre_attack_interval_seconds", 3600),
        opensearch_interval_seconds=intervals.get("opensearch_interval_seconds", 300),
        ti_interval_seconds=intervals.get("ti_interval_seconds", 1800),
    )


@router.put("/intervals", response_model=HealthIntervalResponse)
async def update_health_intervals(
    config: HealthIntervalConfig,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Update health check interval configuration."""
    # Save to settings
    await set_setting(db, "health_check_intervals", config.model_dump())

    # Update scheduler intervals
    from app.services.scheduler import scheduler_service
    await scheduler_service.update_health_check_intervals(config.model_dump())

    return HealthIntervalResponse(
        jira_interval_seconds=config.jira_interval_seconds,
        sigmahq_interval_seconds=config.sigmahq_interval_seconds,
        mitre_attack_interval_seconds=config.mitre_attack_interval_seconds,
        opensearch_interval_seconds=config.opensearch_interval_seconds,
        ti_interval_seconds=config.ti_interval_seconds,
    )


@router.get("/status")
async def get_health_status(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Get health status of all services."""
    services = []

    # OpenSearch - always show if configured
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    opensearch_setting = result.scalar_one_or_none()
    if opensearch_setting:
        # Get most recent health check log for OpenSearch
        log_result = await db.execute(
            select(HealthCheckLog)
            .where(HealthCheckLog.service_type == "opensearch")
            .order_by(HealthCheckLog.checked_at.desc())
            .limit(1)
        )
        latest_log = log_result.scalar_one_or_none()

        services.append({
            "service_type": "opensearch",
            "service_name": "OpenSearch",
            "status": latest_log.status if latest_log else "unknown",
            "last_check": latest_log.checked_at.isoformat() if latest_log and latest_log.checked_at else None
        })

    # Jira - only show if enabled
    result = await db.execute(select(JiraConfig).limit(1))
    jira_config = result.scalar_one_or_none()
    if jira_config and jira_config.is_enabled:
        services.append({
            "service_type": "jira",
            "service_name": "Jira Cloud",
            "status": jira_config.last_health_status or "unknown",
            "last_check": jira_config.last_health_check.isoformat() if jira_config.last_health_check else None
        })

    # AI provider - show if configured
    result = await db.execute(select(Setting).where(Setting.key == "ai"))
    ai_setting = result.scalar_one_or_none()
    if ai_setting:
        ai_config = ai_setting.value or {}
        provider = ai_config.get("ai_provider", "disabled")
        if provider != "disabled":
            last_test = ai_config.get("last_tested")
            last_test_success = ai_config.get("last_test_success")
            # If never tested, show as unknown; otherwise show actual status
            if last_test is None:
                status = "unknown"
            else:
                status = "healthy" if last_test_success else "unhealthy"
            services.append({
                "service_type": "ai",
                "service_name": f"AI ({provider})",
                "status": status,
                "last_check": last_test
            })

    # GeoIP - show if configured
    geoip_result = await db.execute(select(Setting).where(Setting.key == "geoip"))
    geoip_setting = geoip_result.scalar_one_or_none()
    if geoip_setting and geoip_setting.value:
        geoip_config = geoip_setting.value
        # Check if enabled and has license key
        enabled = geoip_config.get("enabled", False)
        has_license = bool(geoip_config.get("license_key"))

        if enabled and has_license:
            # Verify database actually exists and is readable
            from app.services.geoip import GeoIPService
            geoip_service = GeoIPService()
            db_available = geoip_service.is_database_available()

            if db_available:
                # Get database info and check modification time
                try:
                    db_info = geoip_service.get_database_info()
                    if db_info:
                        last_update = db_info["modified_at"]

                        # Check if database is recent (within 30 days)
                        from datetime import datetime, timedelta, UTC
                        try:
                            last_update_dt = datetime.fromisoformat(last_update) if isinstance(last_update, str) else last_update
                            days_ago = (datetime.now(UTC) - last_update_dt).days
                        except (ValueError, TypeError):
                            days_ago = None

                        # Determine status based on database age
                        if days_ago is not None:
                            if days_ago <= 7:
                                status = "healthy"
                            elif days_ago <= 30:
                                status = "warning"
                            else:
                                status = "unhealthy"
                        else:
                            status = "unknown"
                    else:
                        last_update = None
                        status = "unhealthy"  # Enabled but can't read DB info
                except Exception:
                    last_update = None
                    status = "unhealthy"  # Error reading DB info
            else:
                last_update = None
                status = "unhealthy"  # Enabled but database not found

            services.append({
                "service_type": "geoip",
                "service_name": "GeoIP",
                "status": status,
                "last_check": last_update
            })

    # SigmaHQ - show if configured
    result = await db.execute(select(Setting).where(Setting.key == "sigmahq_sync"))
    sigmahq_setting = result.scalar_one_or_none()
    if sigmahq_setting and sigmahq_setting.value:
        sigmahq_config = sigmahq_setting.value
        if sigmahq_config.get("enabled"):
            last_sync = sigmahq_config.get("last_sync")
            services.append({
                "service_type": "sigmahq",
                "service_name": "SigmaHQ",
                "status": "healthy" if last_sync else "unknown",
                "last_check": last_sync
            })

    # MITRE ATT&CK - show if configured
    result = await db.execute(select(Setting).where(Setting.key == "attack_sync"))
    attack_setting = result.scalar_one_or_none()
    if attack_setting and attack_setting.value:
        attack_config = attack_setting.value
        if attack_config.get("enabled"):
            last_sync = attack_config.get("last_sync")
            services.append({
                "service_type": "attack",
                "service_name": "MITRE ATT&CK",
                "status": "healthy" if last_sync else "unknown",
                "last_check": last_sync
            })

    # TI sources - show all enabled
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.is_enabled == True)
    )
    ti_configs = result.scalars().all()
    for config in ti_configs:
        services.append({
            "service_type": config.source_type,
            "service_name": config.source_type.replace("_", " ").title(),
            "status": config.last_health_status or "unknown",
            "last_check": config.last_health_check.isoformat() if config.last_health_check else None
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
                "checked_at": c.checked_at.isoformat() if c.checked_at else None
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
    from app.background.tasks.health_checks import check_jira_health, check_opensearch_health, check_ti_source_health

    if service_type == "jira":
        await check_jira_health(db)
        return {"message": "Jira health check triggered"}
    elif service_type == "opensearch":
        await check_opensearch_health(db)
        return {"message": "OpenSearch health check triggered"}
    elif service_type == "ai":
        # Trigger AI ping
        from app.services.scheduler import scheduler_service
        await scheduler_service._run_ai_ping()
        return {"message": "AI connectivity check triggered"}

    return {"error": "Unknown service"}, 400
