"""Health monitoring endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_opensearch_client, require_admin
from app.background.tasks.health_checks import get_ti_source_display_name
from app.core.circuit_breaker import CircuitState, get_circuit_breaker
from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.setting import Setting
from app.models.ti_config import TISourceConfig
from app.models.user import User
from app.services.health import get_all_indices_health, get_health_history, get_index_health
from app.services.settings import get_setting, set_setting

router = APIRouter(prefix="/health", tags=["health"])

# Display name mappings for AI providers
AI_PROVIDER_DISPLAY_NAMES = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "ollama": "Ollama",
}

# Default values (same as in health_monitor.py)
DEFAULT_NO_DATA_MINUTES = 15
DEFAULT_ERROR_RATE_PERCENT = 5.0
DEFAULT_LATENCY_MS = 1000
DEFAULT_QUEUE_WARNING = 10000
DEFAULT_QUEUE_CRITICAL = 100000
DEFAULT_DATA_FRESHNESS_WARNING_MINUTES = 60
DEFAULT_DATA_FRESHNESS_CRITICAL_MINUTES = 240

# Pull mode default values
DEFAULT_PULL_MAX_RETRIES = 3
DEFAULT_PULL_RETRY_DELAY_SECONDS = 5
DEFAULT_PULL_CONSECUTIVE_FAILURES_WARNING = 3
DEFAULT_PULL_CONSECUTIVE_FAILURES_CRITICAL = 10


class HealthSettingsResponse(BaseModel):
    """Response for health settings."""

    no_data_minutes: int
    error_rate_percent: float
    latency_ms: int
    queue_warning: int
    queue_critical: int
    detection_latency_warning_ms: int
    detection_latency_critical_ms: int
    opensearch_latency_warning_ms: int
    opensearch_latency_critical_ms: int
    data_freshness_warning_minutes: int
    data_freshness_critical_minutes: int


class HealthSettingsUpdate(BaseModel):
    """Request for updating health settings."""

    no_data_minutes: int | None = None
    error_rate_percent: float | None = None
    latency_ms: int | None = None
    queue_warning: int | None = None
    queue_critical: int | None = None
    detection_latency_warning_ms: int = Field(default=2000, ge=100)
    detection_latency_critical_ms: int = Field(default=10000, ge=100)
    opensearch_latency_warning_ms: int = Field(default=1000, ge=100)
    opensearch_latency_critical_ms: int = Field(default=5000, ge=100)
    data_freshness_warning_minutes: int = Field(default=60, ge=1)
    data_freshness_critical_minutes: int = Field(default=240, ge=1)


@router.get("/opensearch")
async def get_opensearch_health(
    _: Annotated[User, Depends(get_current_user)],
):
    """Get OpenSearch availability status from circuit breaker state.

    Lightweight endpoint - reads circuit breaker state, does NOT query OpenSearch.
    """
    cb = get_circuit_breaker(
        "opensearch_alerts",
        failure_threshold=3,
        recovery_timeout=30.0,
    )
    state = cb.get_state()
    return {
        "available": state != CircuitState.OPEN,
        "circuit_state": state.value,
        "failure_count": cb.get_failure_count(),
        "last_failure_time": cb._last_failure_time or None,
    }


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
        detection_latency_warning_ms=thresholds.get("detection_latency_warning_ms", 2000),
        detection_latency_critical_ms=thresholds.get("detection_latency_critical_ms", 10000),
        opensearch_latency_warning_ms=thresholds.get("opensearch_latency_warning_ms", 1000),
        opensearch_latency_critical_ms=thresholds.get("opensearch_latency_critical_ms", 5000),
        data_freshness_warning_minutes=thresholds.get(
            "data_freshness_warning_minutes", DEFAULT_DATA_FRESHNESS_WARNING_MINUTES
        ),
        data_freshness_critical_minutes=thresholds.get(
            "data_freshness_critical_minutes", DEFAULT_DATA_FRESHNESS_CRITICAL_MINUTES
        ),
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
        detection_latency_warning_ms=thresholds.get("detection_latency_warning_ms", 2000),
        detection_latency_critical_ms=thresholds.get("detection_latency_critical_ms", 10000),
        opensearch_latency_warning_ms=thresholds.get("opensearch_latency_warning_ms", 1000),
        opensearch_latency_critical_ms=thresholds.get("opensearch_latency_critical_ms", 5000),
        data_freshness_warning_minutes=thresholds.get(
            "data_freshness_warning_minutes", DEFAULT_DATA_FRESHNESS_WARNING_MINUTES
        ),
        data_freshness_critical_minutes=thresholds.get(
            "data_freshness_critical_minutes", DEFAULT_DATA_FRESHNESS_CRITICAL_MINUTES
        ),
    )


# Health Check Interval Configuration
class HealthIntervalConfig(BaseModel):
    """Health check interval configuration."""

    jira_interval_seconds: int = Field(ge=60, le=86400, default=900)
    sigmahq_interval_seconds: int = Field(ge=60, le=86400, default=3600)
    mitre_attack_interval_seconds: int = Field(ge=60, le=86400, default=3600)
    opensearch_interval_seconds: int = Field(ge=30, le=600, default=300)
    ti_interval_seconds: int = Field(ge=60, le=86400, default=3600)


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


# Pull Mode Settings
class PullModeSettingsResponse(BaseModel):
    """Response for pull mode settings."""

    max_retries: int
    retry_delay_seconds: int
    consecutive_failures_warning: int
    consecutive_failures_critical: int


class PullModeSettingsUpdate(BaseModel):
    """Request for updating pull mode settings."""

    max_retries: int = Field(default=3, ge=1, le=10, description="Max retry attempts for failed polls")
    retry_delay_seconds: int = Field(default=5, ge=1, le=60, description="Delay between retries in seconds")
    consecutive_failures_warning: int = Field(default=3, ge=1, le=50, description="Consecutive failures before warning status")
    consecutive_failures_critical: int = Field(default=10, ge=1, le=100, description="Consecutive failures before critical status")

    @field_validator("consecutive_failures_critical")
    @classmethod
    def critical_greater_than_warning(cls, v: int, info) -> int:
        """Ensure critical threshold is greater than warning threshold."""
        warning = info.data.get("consecutive_failures_warning", 3)
        if v <= warning:
            raise ValueError("consecutive_failures_critical must be greater than consecutive_failures_warning")
        return v


@router.get("/pull-mode/settings", response_model=PullModeSettingsResponse)
async def get_pull_mode_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get pull mode detection settings."""
    setting = await get_setting(db, "pull_mode")
    pull_settings = setting or {}

    return PullModeSettingsResponse(
        max_retries=pull_settings.get("max_retries", DEFAULT_PULL_MAX_RETRIES),
        retry_delay_seconds=pull_settings.get("retry_delay_seconds", DEFAULT_PULL_RETRY_DELAY_SECONDS),
        consecutive_failures_warning=pull_settings.get("consecutive_failures_warning", DEFAULT_PULL_CONSECUTIVE_FAILURES_WARNING),
        consecutive_failures_critical=pull_settings.get("consecutive_failures_critical", DEFAULT_PULL_CONSECUTIVE_FAILURES_CRITICAL),
    )


@router.put("/pull-mode/settings", response_model=PullModeSettingsResponse)
async def update_pull_mode_settings(
    data: PullModeSettingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Update pull mode detection settings."""
    # Get current settings
    current = await get_setting(db, "pull_mode")
    pull_settings = current or {}

    # Apply updates
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        pull_settings[key] = value

    # Save
    await set_setting(db, "pull_mode", pull_settings)

    return PullModeSettingsResponse(
        max_retries=pull_settings.get("max_retries", DEFAULT_PULL_MAX_RETRIES),
        retry_delay_seconds=pull_settings.get("retry_delay_seconds", DEFAULT_PULL_RETRY_DELAY_SECONDS),
        consecutive_failures_warning=pull_settings.get("consecutive_failures_warning", DEFAULT_PULL_CONSECUTIVE_FAILURES_WARNING),
        consecutive_failures_critical=pull_settings.get("consecutive_failures_critical", DEFAULT_PULL_CONSECUTIVE_FAILURES_CRITICAL),
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
            display_name = AI_PROVIDER_DISPLAY_NAMES.get(provider, provider.title())
            services.append({
                "service_type": "ai",
                "service_name": f"AI ({display_name})",
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
                        from datetime import UTC, datetime
                        try:
                            # Parse ISO format string - handle both with and without timezone
                            if isinstance(last_update, str):
                                # Add +00:00 if no timezone info to ensure it's treated as UTC
                                if last_update.find('+') == -1 and last_update.find('Z') == -1:
                                    last_update = last_update + '+00:00'
                                last_update_dt = datetime.fromisoformat(last_update)
                            else:
                                last_update_dt = last_update

                            # Ensure both datetimes are timezone-aware
                            now = datetime.now(UTC)
                            if last_update_dt.tzinfo is None:
                                last_update_dt = last_update_dt.replace(tzinfo=UTC)

                            days_ago = (now - last_update_dt).days
                        except (ValueError, TypeError):
                            days_ago = None

                        # Determine status based on database age
                        if days_ago is not None:
                            # Get configured update interval (default weekly = 7 days)
                            update_interval = geoip_config.get("update_interval", "weekly")
                            interval_days = 7 if update_interval == "weekly" else 30  # weekly or monthly

                            # Calculate thresholds based on interval
                            healthy_threshold = interval_days
                            warning_threshold = interval_days + 7  # Grace period of 7 days

                            if days_ago <= healthy_threshold:
                                status = "healthy"
                            elif days_ago <= warning_threshold:
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
        select(TISourceConfig).where(TISourceConfig.is_enabled.is_(True))
    )
    ti_configs = result.scalars().all()
    for config in ti_configs:
        services.append({
            "service_type": config.source_type,
            "service_name": get_ti_source_display_name(config.source_type),
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

    # Calculate overall status
    # Critical services (opensearch, jira) affect overall as critical
    # TI sources affect overall as degraded (warning), not critical
    overall_status = "healthy"
    critical_services = {"opensearch", "jira"}

    for svc in services:
        svc_status = svc.get("status", "unknown")
        svc_type = svc.get("service_type", "")

        if svc_status == "unhealthy":
            if svc_type in critical_services:
                overall_status = "critical"
            elif overall_status != "critical":
                # TI and other sources only degrade to warning
                overall_status = "degraded"
        elif svc_status == "warning" and overall_status == "healthy":
            overall_status = "warning"

    # Count unhealthy TI sources separately for UI display
    unhealthy_ti_count = sum(
        1 for svc in services
        if svc.get("status") == "unhealthy"
        and svc.get("service_type") not in critical_services
        and svc.get("service_type") not in {"ai", "geoip", "sigmahq", "attack"}
    )

    return {
        "overall_status": overall_status,
        "unhealthy_ti_sources": unhealthy_ti_count,
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
    from app.background.tasks.health_checks import check_jira_health, check_opensearch_health

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


# Pull mode health schema
class PullModeHealthResponse(BaseModel):
    """Health status for pull mode index patterns."""

    index_pattern_id: str
    index_pattern_name: str
    pattern: str
    mode: str
    poll_interval_minutes: int
    last_poll_at: str | None
    last_poll_status: str | None
    last_error: str | None
    status: str  # healthy, warning, critical
    issues: list[str]
    metrics: dict


@router.get("/pull-mode")
async def get_pull_mode_health(
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get health status for all pull mode index patterns."""
    from datetime import UTC, datetime

    from sqlalchemy import func
    from sqlalchemy.orm import selectinload

    from app.models.index_pattern import IndexPattern
    from app.models.rule import Rule, RuleStatus
    from app.services.health_monitor import check_index_data_freshness

    # Load configurable thresholds
    pull_mode_settings = await get_setting(db, "pull_mode") or {}
    failures_warning = pull_mode_settings.get("consecutive_failures_warning", DEFAULT_PULL_CONSECUTIVE_FAILURES_WARNING)
    failures_critical = pull_mode_settings.get("consecutive_failures_critical", DEFAULT_PULL_CONSECUTIVE_FAILURES_CRITICAL)

    # Load health thresholds for data freshness check
    health_thresholds = await get_setting(db, "health_thresholds") or {}
    no_data_minutes = health_thresholds.get("no_data_minutes", DEFAULT_NO_DATA_MINUTES)

    # Get all index patterns with poll state
    result = await db.execute(
        select(IndexPattern)
        .options(selectinload(IndexPattern.poll_state))
    )
    patterns = result.scalars().all()

    # Get count of deployed rules per index pattern
    deployed_rules_result = await db.execute(
        select(Rule.index_pattern_id, func.count(Rule.id).label("count"))
        .where(Rule.status == RuleStatus.DEPLOYED)
        .group_by(Rule.index_pattern_id)
    )
    deployed_rules_by_pattern = {row[0]: row[1] for row in deployed_rules_result}

    pull_patterns = []
    for pattern in patterns:
        # Skip push-only patterns unless in pull-only deployment
        from app.core.config import settings
        if not settings.is_pull_only and pattern.mode != "pull":
            continue

        ps = pattern.poll_state
        status = "healthy"
        issues = []
        notes = []

        # Check if there are any deployed rules for this pattern
        has_deployed_rules = deployed_rules_by_pattern.get(pattern.id, 0) > 0

        if ps:
            # Check poll status
            if ps.last_poll_status == "error":
                status = "warning" if ps.consecutive_failures < failures_warning else "critical"
                issues.append(f"Last poll failed: {ps.last_error}")

            # Check consecutive failures against configurable thresholds
            if ps.consecutive_failures >= failures_critical:
                status = "critical"
                issues.append(f"{ps.consecutive_failures} consecutive poll failures")
            elif ps.consecutive_failures >= failures_warning:
                if status != "critical":
                    status = "warning"
                issues.append(f"{ps.consecutive_failures} consecutive poll failures")

            # Check time since last poll
            if ps.last_poll_at:
                time_since = datetime.now(UTC) - ps.last_poll_at.replace(tzinfo=UTC)
                expected_interval = pattern.poll_interval_minutes * 60 * 2  # 2x expected interval
                if time_since.total_seconds() > expected_interval:
                    if has_deployed_rules:
                        # Only warn if there are enabled rules that should be polling
                        if status != "critical":
                            status = "warning"
                        issues.append(f"No poll in {int(time_since.total_seconds() / 60)} minutes (expected every {pattern.poll_interval_minutes})")
                    else:
                        # No enabled rules - polling paused is expected, not a warning
                        notes.append("Polling paused - no enabled rules")

            metrics = {
                "total_polls": ps.total_polls,
                "successful_polls": ps.successful_polls,
                "failed_polls": ps.failed_polls,
                "success_rate": round(ps.successful_polls / ps.total_polls * 100, 1) if ps.total_polls > 0 else 0,
                "total_matches": ps.total_matches,
                "total_events_scanned": ps.total_events_scanned,
                "last_poll_duration_ms": ps.last_poll_duration_ms,
                "avg_poll_duration_ms": round(ps.avg_poll_duration_ms, 1) if ps.avg_poll_duration_ms else None,
                "consecutive_failures": ps.consecutive_failures,
            }
        else:
            # No poll state yet - pattern hasn't been polled
            if has_deployed_rules:
                status = "warning"
                issues.append("Pattern not yet polled")
            else:
                # No enabled rules - no polling expected
                notes.append("Polling paused - no enabled rules")
            metrics = {
                "total_polls": 0,
                "successful_polls": 0,
                "failed_polls": 0,
                "success_rate": 0,
                "total_matches": 0,
                "total_events_scanned": 0,
                "last_poll_duration_ms": None,
                "avg_poll_duration_ms": None,
                "consecutive_failures": 0,
            }

        # Check data freshness for this pattern
        data_freshness = None
        try:
            # Use pattern-specific threshold if set, otherwise global
            threshold = pattern.health_no_data_minutes or no_data_minutes
            _, freshness_details = await check_index_data_freshness(
                os_client,
                pattern,
                threshold_minutes=threshold
            )
            data_freshness = freshness_details
        except Exception as e:
            data_freshness = {
                "status": "error",
                "message": f"Failed to check data freshness: {e}",
                "index": pattern.pattern,
            }

        pull_patterns.append({
            "index_pattern_id": str(pattern.id),
            "index_pattern_name": pattern.name,
            "pattern": pattern.pattern,
            "mode": pattern.mode,
            "poll_interval_minutes": pattern.poll_interval_minutes,
            "last_poll_at": ps.last_poll_at.isoformat() if ps and ps.last_poll_at else None,
            "last_poll_status": ps.last_poll_status if ps else None,
            "last_error": ps.last_error if ps else None,
            "status": status,
            "issues": issues,
            "notes": notes,
            "has_enabled_rules": has_deployed_rules,
            "metrics": metrics,
            "data_freshness": data_freshness,
        })

    # Calculate overall status
    overall_status = "healthy"
    if any(p["status"] == "critical" for p in pull_patterns):
        overall_status = "critical"
    elif any(p["status"] == "warning" for p in pull_patterns):
        overall_status = "warning"

    # Aggregate metrics
    total_metrics = {
        "total_patterns": len(pull_patterns),
        "healthy_patterns": sum(1 for p in pull_patterns if p["status"] == "healthy"),
        "warning_patterns": sum(1 for p in pull_patterns if p["status"] == "warning"),
        "critical_patterns": sum(1 for p in pull_patterns if p["status"] == "critical"),
        "total_polls": sum(p["metrics"]["total_polls"] for p in pull_patterns),
        "total_matches": sum(p["metrics"]["total_matches"] for p in pull_patterns),
        "total_events_scanned": sum(p["metrics"]["total_events_scanned"] for p in pull_patterns),
    }

    return {
        "overall_status": overall_status,
        "summary": total_metrics,
        "patterns": pull_patterns,
    }
