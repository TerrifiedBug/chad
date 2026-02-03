"""MISP feedback API endpoints."""

import logging
from datetime import datetime, UTC
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.encryption import decrypt
from app.models.ti_config import TISourceConfig, TISourceType
from app.models.user import User
from app.services.ti.misp_feedback import MISPFeedbackService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/misp/feedback", tags=["MISP Feedback"])


class SightingRequest(BaseModel):
    """Request body for recording a sighting."""

    attribute_uuid: str
    source: str = "CHAD"
    is_false_positive: bool = False


class SightingResponse(BaseModel):
    """Response for sighting recording."""

    success: bool
    sighting_id: str | None = None
    error: str | None = None


class EventRequest(BaseModel):
    """Request body for creating an event."""

    alert_id: str | None = None
    info: str
    threat_level: int = 2  # Medium
    distribution: int = 0  # Your org only
    tags: list[str] = []
    attributes: list[dict[str, Any]] = []


class EventResponse(BaseModel):
    """Response for event creation."""

    success: bool
    event_id: str | None = None
    event_uuid: str | None = None
    error: str | None = None


async def create_feedback_service(db: AsyncSession) -> MISPFeedbackService:
    """Create MISP feedback service from configuration."""
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

    verify_tls = config.config.get("verify_tls", True) if config.config else True

    client = httpx.AsyncClient(
        base_url=config.instance_url.rstrip("/"),
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        timeout=30,
        verify=verify_tls,
    )

    return MISPFeedbackService(client)


@router.post("/sighting", response_model=SightingResponse)
async def record_sighting(
    request: SightingRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Record a sighting in MISP."""
    service = await create_feedback_service(db)

    sighting_type = 1 if request.is_false_positive else 0

    result = await service.record_sighting(
        attribute_uuid=request.attribute_uuid,
        source=request.source,
        timestamp=datetime.now(UTC),
        sighting_type=sighting_type,
    )

    return SightingResponse(
        success=result.success,
        sighting_id=result.sighting_id,
        error=result.error,
    )


@router.post("/event", response_model=EventResponse)
async def create_event(
    request: EventRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a MISP event from an alert."""
    service = await create_feedback_service(db)

    # Add to_ids: True to all attributes if not specified
    attributes = []
    for attr in request.attributes:
        attr_copy = dict(attr)
        if "to_ids" not in attr_copy:
            attr_copy["to_ids"] = True
        attributes.append(attr_copy)

    # Add source:chad tag
    tags = list(request.tags)
    if "source:chad" not in tags:
        tags.append("source:chad")

    result = await service.create_event(
        info=request.info,
        threat_level=request.threat_level,
        distribution=request.distribution,
        tags=tags,
        attributes=attributes,
    )

    return EventResponse(
        success=result.success,
        event_id=result.event_id,
        event_uuid=result.event_uuid,
        error=result.error,
    )
