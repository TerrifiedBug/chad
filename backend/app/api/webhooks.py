"""
Webhooks API endpoints.

Manage webhook endpoints for notifications. Admin access required.
"""

from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.notification_settings import Webhook
from app.models.user import User
from app.schemas.webhook import (
    WebhookCreate,
    WebhookResponse,
    WebhookTestResponse,
    WebhookUpdate,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all configured webhooks."""
    result = await db.execute(select(Webhook).order_by(Webhook.name))
    webhooks = result.scalars().all()
    return [
        WebhookResponse(
            id=w.id,
            name=w.name,
            url=w.url,
            has_auth=bool(w.auth_header),
            enabled=w.enabled,
            created_at=w.created_at,
            updated_at=w.updated_at,
        )
        for w in webhooks
    ]


@router.post("", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    data: WebhookCreate,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new webhook."""
    # Check for duplicate name
    existing = await db.execute(select(Webhook).where(Webhook.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A webhook with this name already exists",
        )

    webhook = Webhook(
        name=data.name,
        url=str(data.url),
        auth_header=encrypt(data.auth_header) if data.auth_header else None,
        enabled=data.enabled,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)

    await audit_log(
        db,
        current_user.id,
        "webhook.create",
        "webhook",
        str(webhook.id),
        {"name": webhook.name, "url": webhook.url},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        has_auth=bool(webhook.auth_header),
        enabled=webhook.enabled,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: UUID,
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific webhook by ID."""
    webhook = await db.get(Webhook, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        has_auth=bool(webhook.auth_header),
        enabled=webhook.enabled,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: UUID,
    data: WebhookUpdate,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update a webhook."""
    webhook = await db.get(Webhook, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if data.name is not None:
        webhook.name = data.name
    if data.url is not None:
        webhook.url = str(data.url)
    if data.auth_header is not None:
        webhook.auth_header = encrypt(data.auth_header) if data.auth_header else None
    if data.enabled is not None:
        webhook.enabled = data.enabled

    await audit_log(
        db,
        current_user.id,
        "webhook.update",
        "webhook",
        str(webhook_id),
        {"name": webhook.name, "url": webhook.url, "enabled": webhook.enabled},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(webhook)

    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        has_auth=bool(webhook.auth_header),
        enabled=webhook.enabled,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a webhook."""
    webhook = await db.get(Webhook, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    name = webhook.name  # Capture before delete
    await db.delete(webhook)
    await audit_log(
        db,
        current_user.id,
        "webhook.delete",
        "webhook",
        str(webhook_id),
        {"name": name},
        ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: UUID,
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Send a test message to the webhook."""
    webhook = await db.get(Webhook, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    headers = {"Content-Type": "application/json"}
    if webhook.auth_header:
        headers["Authorization"] = decrypt(webhook.auth_header)

    payload = {
        "type": "test",
        "message": "Test notification from CHAD",
        "webhook_name": webhook.name,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=10.0,
            )
            return WebhookTestResponse(
                success=response.is_success,
                status_code=response.status_code,
            )
    except Exception as e:
        return WebhookTestResponse(
            success=False,
            error=str(e),
        )
