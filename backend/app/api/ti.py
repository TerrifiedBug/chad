"""Threat Intelligence configuration API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.ti_config import TISourceConfig, TISourceType
from app.models.user import User
from app.services.audit import audit_log
from app.services.ti import (
    AbuseCHClient,
    AbuseIPDBClient,
    AlienVaultOTXClient,
    GreyNoiseClient,
    MISPClient,
    PhishTankClient,
    ThreatFoxClient,
    VirusTotalClient,
)
from app.utils.request import get_client_ip

router = APIRouter(prefix="/ti", tags=["threat-intelligence"])


# Request/Response models
class TISourceConfigUpdate(BaseModel):
    """Request model for updating TI source configuration."""

    is_enabled: bool = False
    api_key: str | None = None  # Optional on update if not changing
    instance_url: str | None = None
    config: dict | None = None


class TISourceConfigResponse(BaseModel):
    """Response model for TI source configuration."""

    id: str
    source_type: str
    is_enabled: bool
    has_api_key: bool
    instance_url: str | None
    config: dict | None


class TISourcesStatus(BaseModel):
    """Response for listing all TI sources."""

    sources: list[TISourceConfigResponse]


class TITestResponse(BaseModel):
    """Response model for TI source connection test."""

    success: bool
    error: str | None = None


def _source_to_response(config: TISourceConfig) -> TISourceConfigResponse:
    """Convert a TISourceConfig to API response."""
    return TISourceConfigResponse(
        id=str(config.id),
        source_type=config.source_type,
        is_enabled=config.is_enabled,
        has_api_key=bool(config.api_key_encrypted),
        instance_url=config.instance_url,
        config=config.config,
    )


@router.get("", response_model=TISourcesStatus)
async def list_ti_sources(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """List all TI source configurations (admin only)."""
    result = await db.execute(select(TISourceConfig))
    configs = result.scalars().all()

    # Return all possible sources, indicating which are configured
    sources = []
    configured_types = {c.source_type: c for c in configs}

    for source_type in TISourceType:
        if source_type.value in configured_types:
            sources.append(_source_to_response(configured_types[source_type.value]))
        else:
            # Return unconfigured source placeholder
            sources.append(
                TISourceConfigResponse(
                    id="",
                    source_type=source_type.value,
                    is_enabled=False,
                    has_api_key=False,
                    instance_url=None,
                    config=None,
                )
            )

    return TISourcesStatus(sources=sources)


@router.get("/{source_type}", response_model=TISourceConfigResponse)
async def get_ti_source(
    source_type: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get configuration for a specific TI source (admin only)."""
    # Validate source type
    try:
        TISourceType(source_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source type: {source_type}",
        )

    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.source_type == source_type)
    )
    config = result.scalar_one_or_none()

    if not config:
        # Return unconfigured source placeholder
        return TISourceConfigResponse(
            id="",
            source_type=source_type,
            is_enabled=False,
            has_api_key=False,
            instance_url=None,
            config=None,
        )

    return _source_to_response(config)


@router.put("/{source_type}", response_model=TISourceConfigResponse)
async def update_ti_source(
    source_type: str,
    data: TISourceConfigUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Create or update TI source configuration (admin only)."""
    # Validate source type
    try:
        TISourceType(source_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source type: {source_type}",
        )

    # Get existing config
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.source_type == source_type)
    )
    config = result.scalar_one_or_none()

    if config:
        # Update existing
        config.is_enabled = data.is_enabled
        config.instance_url = data.instance_url
        config.config = data.config

        # Only update API key if provided
        if data.api_key:
            config.api_key_encrypted = encrypt(data.api_key)
    else:
        # Create new
        config = TISourceConfig(
            source_type=source_type,
            is_enabled=data.is_enabled,
            api_key_encrypted=encrypt(data.api_key) if data.api_key else None,
            instance_url=data.instance_url,
            config=data.config,
        )
        db.add(config)

    await audit_log(
        db,
        current_user.id,
        "ti.update",
        "ti_source_config",
        source_type,
        {"source_type": source_type, "is_enabled": data.is_enabled},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(config)

    return _source_to_response(config)


@router.delete("/{source_type}")
async def delete_ti_source(
    source_type: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Delete TI source configuration (admin only)."""
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.source_type == source_type)
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TI source configuration not found: {source_type}",
        )

    await db.delete(config)
    await audit_log(
        db,
        current_user.id,
        "ti.delete",
        "ti_source_config",
        source_type,
        {},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"success": True}


@router.post("/{source_type}/test", response_model=TITestResponse)
async def test_ti_source(
    source_type: str,
    data: TISourceConfigUpdate,
    _: Annotated[User, Depends(require_admin)],
):
    """Test TI source connection with provided credentials (admin only)."""
    # Validate source type
    try:
        TISourceType(source_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source type: {source_type}",
        )

    # Create temporary client for testing
    client = None
    try:
        match source_type:
            case TISourceType.VIRUSTOTAL.value:
                if not data.api_key:
                    return TITestResponse(success=False, error="API key required")
                client = VirusTotalClient(data.api_key)

            case TISourceType.ABUSEIPDB.value:
                if not data.api_key:
                    return TITestResponse(success=False, error="API key required")
                client = AbuseIPDBClient(data.api_key)

            case TISourceType.GREYNOISE.value:
                if not data.api_key:
                    return TITestResponse(success=False, error="API key required")
                client = GreyNoiseClient(data.api_key)

            case TISourceType.THREATFOX.value:
                # ThreatFox doesn't require an API key
                client = ThreatFoxClient(data.api_key)

            case TISourceType.MISP.value:
                if not data.api_key:
                    return TITestResponse(success=False, error="API key required")
                if not data.instance_url:
                    return TITestResponse(success=False, error="Instance URL required")
                # Get verify_tls from config, default True
                verify_tls = data.config.get("verify_tls", True) if data.config else True
                client = MISPClient(data.api_key, data.instance_url, verify_tls=verify_tls)

            case TISourceType.ABUSE_CH.value:
                # abuse.ch doesn't require an API key
                client = AbuseCHClient(data.api_key)

            case TISourceType.ALIENVAULT_OTX.value:
                if not data.api_key:
                    return TITestResponse(success=False, error="API key required")
                client = AlienVaultOTXClient(data.api_key)

            case TISourceType.PHISHTANK.value:
                # PhishTank API key is optional
                client = PhishTankClient(data.api_key)

            case _:
                return TITestResponse(success=False, error=f"Unknown source: {source_type}")

        success = await client.test_connection()
        return TITestResponse(success=success, error=None if success else "Connection test failed")

    except Exception as e:
        return TITestResponse(success=False, error=str(e))
    finally:
        if client:
            await client.close()


@router.post("/{source_type}/test-saved", response_model=TITestResponse)
async def test_saved_ti_source(
    source_type: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Test connection using saved TI source configuration (admin only)."""
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.source_type == source_type)
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TI source configuration not found: {source_type}",
        )

    # Decrypt API key
    api_key = None
    if config.api_key_encrypted:
        api_key = decrypt(config.api_key_encrypted)

    # Create client for testing
    client = None
    try:
        match source_type:
            case TISourceType.VIRUSTOTAL.value:
                if not api_key:
                    return TITestResponse(success=False, error="API key not configured")
                client = VirusTotalClient(api_key)

            case TISourceType.ABUSEIPDB.value:
                if not api_key:
                    return TITestResponse(success=False, error="API key not configured")
                client = AbuseIPDBClient(api_key)

            case TISourceType.GREYNOISE.value:
                if not api_key:
                    return TITestResponse(success=False, error="API key not configured")
                client = GreyNoiseClient(api_key)

            case TISourceType.THREATFOX.value:
                client = ThreatFoxClient(api_key)

            case TISourceType.MISP.value:
                if not api_key:
                    return TITestResponse(success=False, error="API key not configured")
                if not config.instance_url:
                    return TITestResponse(success=False, error="Instance URL not configured")
                # Get verify_tls from config, default True
                verify_tls = config.config.get("verify_tls", True) if config.config else True
                client = MISPClient(api_key, config.instance_url, verify_tls=verify_tls)

            case TISourceType.ABUSE_CH.value:
                # abuse.ch doesn't require an API key
                client = AbuseCHClient(api_key)

            case TISourceType.ALIENVAULT_OTX.value:
                if not api_key:
                    return TITestResponse(success=False, error="API key not configured")
                client = AlienVaultOTXClient(api_key)

            case TISourceType.PHISHTANK.value:
                # PhishTank API key is optional
                client = PhishTankClient(api_key)

            case _:
                return TITestResponse(success=False, error=f"Unknown source: {source_type}")

        success = await client.test_connection()
        return TITestResponse(success=success, error=None if success else "Connection test failed")

    except Exception as e:
        return TITestResponse(success=False, error=str(e))
    finally:
        if client:
            await client.close()
