"""MISP sync API endpoints."""

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_opensearch_client_optional
from app.core.encryption import decrypt
from app.models.setting import Setting
from app.models.ti_config import TISourceConfig, TISourceType
from app.models.user import User
from app.services.ti.ioc_cache import IOCCache
from app.services.ti.ioc_index import IOCIndexService
from app.services.ti.ioc_types import IOCType
from app.services.ti.misp_sync import MISPIOCFetcher
from app.services.ti.misp_sync_service import MISPSyncService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/misp/sync", tags=["MISP Sync"])


class SyncConfigRequest(BaseModel):
    """Request body for updating sync config."""

    enabled: bool = False
    interval_minutes: int = 10
    threat_levels: list[str] = ["high", "medium", "low", "undefined"]
    max_age_days: int = 30
    ttl_days: int = 30
    tags: list[str] | None = None
    ioc_types: list[str] | None = None


class SyncStatusResponse(BaseModel):
    """Response for sync status."""

    last_sync_at: str | None = None
    iocs_synced: int = 0
    sync_duration_ms: int = 0
    redis_ioc_count: int = 0
    opensearch_ioc_count: int = 0
    error_message: str | None = None


class SyncTriggerResponse(BaseModel):
    """Response for manual sync trigger."""

    success: bool
    iocs_fetched: int = 0
    iocs_cached: int = 0
    iocs_indexed: int = 0
    duration_ms: int = 0
    error: str | None = None


async def get_sync_status_from_db(db: AsyncSession, os_client=None) -> dict[str, Any]:
    """Get sync status from database and services."""
    # Get last sync info from settings
    result = await db.execute(
        select(Setting).where(Setting.key == "misp_sync_status")
    )
    status_setting = result.scalar_one_or_none()

    status = {}
    if status_setting and status_setting.value:
        status = status_setting.value

    # Get current IOC counts
    try:
        cache = IOCCache()
        status["redis_ioc_count"] = await cache.get_ioc_count()
    except Exception as e:
        logger.warning("Could not get Redis IOC count: %s", e)
        status["redis_ioc_count"] = 0

    if os_client:
        try:
            index_service = IOCIndexService(os_client)
            status["opensearch_ioc_count"] = await index_service.get_ioc_count()
        except Exception as e:
            logger.warning("Could not get OpenSearch IOC count: %s", e)
            status["opensearch_ioc_count"] = 0
    else:
        status["opensearch_ioc_count"] = 0

    return status


async def trigger_misp_sync(db: AsyncSession, os_client=None) -> dict[str, Any]:
    """Trigger a manual MISP sync."""
    # Get MISP config
    result = await db.execute(
        select(TISourceConfig).where(
            TISourceConfig.source_type == TISourceType.MISP,
            TISourceConfig.is_enabled.is_(True),
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(400, "MISP source not configured or not enabled")

    api_key = decrypt(config.api_key_encrypted) if config.api_key_encrypted else None
    if not api_key:
        raise HTTPException(400, "MISP API key not configured")

    if not config.instance_url:
        raise HTTPException(400, "MISP instance URL not configured")

    if not os_client:
        raise HTTPException(400, "OpenSearch not configured")

    verify_tls = config.config.get("verify_tls", True) if config.config else True

    # Get sync settings
    result = await db.execute(
        select(Setting).where(Setting.key == "misp_sync")
    )
    settings_row = result.scalar_one_or_none()
    settings = settings_row.value if settings_row and settings_row.value else {}

    # Create services
    fetcher = MISPIOCFetcher(
        api_key=api_key,
        instance_url=config.instance_url,
        verify_tls=verify_tls,
    )
    cache = IOCCache()
    index_service = IOCIndexService(os_client)

    # Ensure index exists
    await index_service.ensure_index()

    service = MISPSyncService(fetcher, cache, index_service)

    # Run sync
    threat_levels = settings.get("threat_levels", ["high", "medium", "low", "undefined"])
    max_age_days = settings.get("max_age_days", 30)
    ttl_days = settings.get("ttl_days", 30)
    tags = settings.get("tags")
    ioc_types = None
    if settings.get("ioc_types"):
        ioc_types = [IOCType(t) for t in settings["ioc_types"]]

    sync_result = await service.sync_iocs(
        threat_levels=threat_levels,
        ioc_types=ioc_types,
        max_age_days=max_age_days,
        tags=tags,
        ttl_days=ttl_days,
    )

    # Update status in database
    status_result = await db.execute(
        select(Setting).where(Setting.key == "misp_sync_status")
    )
    status_setting = status_result.scalar_one_or_none()

    status_value = {
        "last_sync_at": datetime.now(UTC).isoformat(),
        "iocs_synced": sync_result.iocs_fetched,
        "sync_duration_ms": sync_result.duration_ms,
        "error_message": sync_result.error,
    }

    if status_setting:
        status_setting.value = status_value
    else:
        db.add(Setting(key="misp_sync_status", value=status_value))

    await db.commit()

    await fetcher.close()

    return {
        "success": sync_result.success,
        "iocs_fetched": sync_result.iocs_fetched,
        "iocs_cached": sync_result.iocs_cached,
        "iocs_indexed": sync_result.iocs_indexed,
        "duration_ms": sync_result.duration_ms,
        "error": sync_result.error,
    }


@router.get("/status", response_model=SyncStatusResponse)
async def get_sync_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    os_client=Depends(get_opensearch_client_optional),
):
    """Get MISP sync status."""
    status = await get_sync_status_from_db(db, os_client)
    return SyncStatusResponse(**status)


@router.post("/trigger", response_model=SyncTriggerResponse)
async def trigger_sync(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    os_client=Depends(get_opensearch_client_optional),
):
    """Trigger a manual MISP IOC sync."""
    result = await trigger_misp_sync(db, os_client)
    return SyncTriggerResponse(**result)


@router.get("/config")
async def get_sync_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MISP sync configuration."""
    result = await db.execute(
        select(Setting).where(Setting.key == "misp_sync")
    )
    setting = result.scalar_one_or_none()

    if setting and setting.value:
        return setting.value

    # Return defaults
    return {
        "enabled": False,
        "interval_minutes": 10,
        "threat_levels": ["high", "medium", "low", "undefined"],
        "max_age_days": 30,
        "ttl_days": 30,
    }


@router.put("/config")
async def update_sync_config(
    config: SyncConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update MISP sync configuration."""
    result = await db.execute(
        select(Setting).where(Setting.key == "misp_sync")
    )
    setting = result.scalar_one_or_none()

    config_dict = config.model_dump()

    if setting:
        setting.value = config_dict
    else:
        db.add(Setting(key="misp_sync", value=config_dict))

    await db.commit()

    return config_dict
