"""API endpoints for enrichment webhook management."""

import logging
import time
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_admin
from app.core.audit import audit_action, log_audit
from app.core.encryption import decrypt, encrypt
from app.models.enrichment_webhook import EnrichmentWebhook
from app.models.user import User
from app.schemas.enrichment_webhook import (
    EnrichmentWebhookCreate,
    EnrichmentWebhookResponse,
    EnrichmentWebhookTestRequest,
    EnrichmentWebhookTestResponse,
    EnrichmentWebhookUpdate,
)
from app.services.webhooks import sanitize_webhook_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/enrichment-webhooks", tags=["enrichment-webhooks"])


def _webhook_to_response(webhook: EnrichmentWebhook) -> EnrichmentWebhookResponse:
    """Convert model to response schema."""
    return EnrichmentWebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        namespace=webhook.namespace,
        method=webhook.method,
        header_name=webhook.header_name,
        has_credentials=webhook.header_value_encrypted is not None,
        timeout_seconds=webhook.timeout_seconds,
        max_concurrent_calls=webhook.max_concurrent_calls,
        cache_ttl_seconds=webhook.cache_ttl_seconds,
        is_active=webhook.is_active,
        include_ioc_alerts=webhook.include_ioc_alerts,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


@router.get("", response_model=list[EnrichmentWebhookResponse])
async def list_enrichment_webhooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """List all enrichment webhooks."""
    result = await db.execute(
        select(EnrichmentWebhook).order_by(EnrichmentWebhook.name)
    )
    webhooks = result.scalars().all()
    return [_webhook_to_response(w) for w in webhooks]


@router.post("", response_model=EnrichmentWebhookResponse, status_code=status.HTTP_201_CREATED)
@audit_action("create", "enrichment_webhook", lambda r: str(r.id), lambda r: {"name": r.name, "namespace": r.namespace})
async def create_enrichment_webhook(
    data: EnrichmentWebhookCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Create a new enrichment webhook."""
    # Validate URL for SSRF
    sanitized_url, error_msg = sanitize_webhook_url(data.url)
    if sanitized_url is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid webhook URL: {error_msg}",
        )

    # Check namespace uniqueness
    existing = await db.execute(
        select(EnrichmentWebhook).where(EnrichmentWebhook.namespace == data.namespace.lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Namespace '{data.namespace}' already exists",
        )

    webhook = EnrichmentWebhook(
        name=data.name,
        url=sanitized_url,
        namespace=data.namespace.lower(),
        method=data.method,
        header_name=data.header_name,
        header_value_encrypted=encrypt(data.header_value) if data.header_value else None,
        timeout_seconds=data.timeout_seconds,
        max_concurrent_calls=data.max_concurrent_calls,
        cache_ttl_seconds=data.cache_ttl_seconds,
        is_active=data.is_active,
        include_ioc_alerts=data.include_ioc_alerts,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)

    logger.info("Created enrichment webhook: %s", webhook.name)
    return _webhook_to_response(webhook)


@router.get("/{webhook_id}", response_model=EnrichmentWebhookResponse)
async def get_enrichment_webhook(
    webhook_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Get a single enrichment webhook."""
    result = await db.execute(
        select(EnrichmentWebhook).where(EnrichmentWebhook.id == webhook_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return _webhook_to_response(webhook)


@router.patch("/{webhook_id}", response_model=EnrichmentWebhookResponse)
@audit_action("update", "enrichment_webhook", lambda r: str(r.id), lambda r: {"name": r.name})
async def update_enrichment_webhook(
    webhook_id: UUID,
    data: EnrichmentWebhookUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Update an enrichment webhook."""
    result = await db.execute(
        select(EnrichmentWebhook).where(EnrichmentWebhook.id == webhook_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    update_data = data.model_dump(exclude_unset=True)

    # Validate URL if being updated
    if "url" in update_data:
        sanitized_url, error_msg = sanitize_webhook_url(update_data["url"])
        if sanitized_url is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid webhook URL: {error_msg}",
            )
        update_data["url"] = sanitized_url

    # Handle credential update
    if "header_value" in update_data:
        value = update_data.pop("header_value")
        update_data["header_value_encrypted"] = encrypt(value) if value else None

    for key, value in update_data.items():
        setattr(webhook, key, value)

    await db.commit()
    await db.refresh(webhook)

    logger.info("Updated enrichment webhook: %s", webhook.name)
    return _webhook_to_response(webhook)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_enrichment_webhook(
    webhook_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Delete an enrichment webhook."""
    result = await db.execute(
        select(EnrichmentWebhook).where(EnrichmentWebhook.id == webhook_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    # Capture info for audit before deletion
    webhook_name = webhook.name
    webhook_namespace = webhook.namespace

    await db.delete(webhook)

    # Audit log the deletion
    await log_audit(
        db=db,
        action="delete",
        resource_type="enrichment_webhook",
        resource_id=str(webhook_id),
        user=current_user,
        details={"name": webhook_name, "namespace": webhook_namespace},
    )

    await db.commit()
    logger.info("Deleted enrichment webhook: %s", webhook_name)


@router.post("/{webhook_id}/test", response_model=EnrichmentWebhookTestResponse)
async def test_enrichment_webhook(
    webhook_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Test an enrichment webhook with sample data."""
    result = await db.execute(
        select(EnrichmentWebhook).where(EnrichmentWebhook.id == webhook_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    # Build test payload
    test_payload = {
        "alert_id": "test-alert-123",
        "rule_id": "test-rule-456",
        "rule_title": "Test Rule - Webhook Verification",
        "severity": "informational",
        "lookup_field": "user.name",
        "lookup_value": "testuser@example.com",
        "log_document": {
            "@timestamp": "2026-02-04T12:00:00Z",
            "user.name": "testuser@example.com",
            "host.name": "TEST-WORKSTATION",
            "source.ip": "10.0.1.100",
        },
    }

    # Validate URL
    sanitized_url, error_msg = sanitize_webhook_url(webhook.url)
    if sanitized_url is None:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=f"URL blocked by SSRF protection: {error_msg}",
        )

    # Build headers
    headers = {"Content-Type": "application/json"}
    if webhook.header_name and webhook.header_value_encrypted:
        try:
            headers[webhook.header_name] = decrypt(webhook.header_value_encrypted)
        except Exception:
            return EnrichmentWebhookTestResponse(
                success=False,
                error="Failed to decrypt credentials",
            )

    # Make request
    start_time = time.monotonic()
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=webhook.method,
                url=sanitized_url,
                json=test_payload,
                headers=headers,
                timeout=webhook.timeout_seconds,
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        # Try to parse response as JSON
        try:
            response_body = response.json()
        except Exception:
            response_body = None

        return EnrichmentWebhookTestResponse(
            success=response.status_code < 400,
            status_code=response.status_code,
            response_body=response_body,
            duration_ms=duration_ms,
        )

    except httpx.TimeoutException:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=f"Request timed out after {webhook.timeout_seconds}s",
            duration_ms=int((time.monotonic() - start_time) * 1000),
        )
    except Exception as e:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=str(e),
            duration_ms=int((time.monotonic() - start_time) * 1000),
        )


@router.post("/test", response_model=EnrichmentWebhookTestResponse)
async def test_webhook_url(
    data: EnrichmentWebhookTestRequest,
    current_user: Annotated[User, Depends(require_admin)],
):
    """Test a webhook URL before saving (for new webhook creation)."""
    # Validate URL
    sanitized_url, error_msg = sanitize_webhook_url(data.url)
    if sanitized_url is None:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=f"URL blocked by SSRF protection: {error_msg}",
        )

    test_payload = {
        "alert_id": "test-alert-123",
        "rule_id": "test-rule-456",
        "rule_title": "Test Rule - Webhook Verification",
        "severity": "informational",
        "lookup_field": "user.name",
        "lookup_value": "testuser@example.com",
        "log_document": {"user.name": "testuser@example.com"},
    }

    headers = {"Content-Type": "application/json"}
    if data.header_name and data.header_value:
        headers[data.header_name] = data.header_value

    start_time = time.monotonic()
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=data.method,
                url=sanitized_url,
                json=test_payload,
                headers=headers,
                timeout=data.timeout_seconds,
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        try:
            response_body = response.json()
        except Exception:
            response_body = None

        return EnrichmentWebhookTestResponse(
            success=response.status_code < 400,
            status_code=response.status_code,
            response_body=response_body,
            duration_ms=duration_ms,
        )

    except httpx.TimeoutException:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=f"Request timed out after {data.timeout_seconds}s",
            duration_ms=int((time.monotonic() - start_time) * 1000),
        )
    except Exception as e:
        return EnrichmentWebhookTestResponse(
            success=False,
            error=str(e),
            duration_ms=int((time.monotonic() - start_time) * 1000),
        )
