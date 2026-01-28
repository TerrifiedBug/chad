"""
Webhooks API endpoints.

Manage webhook endpoints for notifications. Admin access required.
"""

import ipaddress
from typing import Annotated
from urllib.parse import urlparse
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


def is_safe_webhook_url(url: str) -> tuple[bool, str | None]:
    """Validate webhook URL is safe and doesn't point to internal services.

    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False, "Invalid URL: no hostname"

        # Block private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"Cannot use private IP: {hostname}"
        except ValueError:
            # Not an IP address, continue with hostname checks
            pass

        # Block metadata endpoints
        if hostname == "169.254.169.254":
            return False, "Cloud metadata endpoint not allowed"

        # Block localhost variants
        blocked_hostnames = {
            "localhost", "127.0.0.1", "[::1]", "0.0.0.0",
            "localhost.localdomain", "ip6-localhost", "ip6-loopback"
        }
        if hostname.lower() in blocked_hostnames:
            return False, f"Cannot use localhost: {hostname}"

        # Block internal hostname patterns
        hostname_lower = hostname.lower()
        internal_patterns = [
            ".internal.", ".local.", ".corp.", ".private.",
            ".intranet.", ".lan.", "localhost"
        ]
        if any(pattern in hostname_lower for pattern in internal_patterns):
            return False, f"Internal hostname not allowed: {hostname}"

        return True, None

    except Exception as e:
        return False, "Invalid URL format"


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
            has_auth=bool(w.header_value),
            header_name=w.header_name,
            provider=w.provider,
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
    # Validate URL is safe
    is_safe, error_msg = is_safe_webhook_url(str(data.url))
    if not is_safe:
        raise HTTPException(status_code=400, detail=error_msg)

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
        header_name=data.header_name,
        header_value=encrypt(data.header_value) if data.header_value else None,
        provider=data.provider.value,
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
        has_auth=bool(webhook.header_value),
        header_name=webhook.header_name,
        provider=webhook.provider,
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
        has_auth=bool(webhook.header_value),
        header_name=webhook.header_name,
        provider=webhook.provider,
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

    # Validate URL if being updated
    if data.url is not None:
        is_safe, error_msg = is_safe_webhook_url(str(data.url))
        if not is_safe:
            raise HTTPException(status_code=400, detail=error_msg)

    if data.name is not None:
        webhook.name = data.name
    if data.url is not None:
        webhook.url = str(data.url)
    if data.header_name is not None:
        webhook.header_name = data.header_name if data.header_name else None
    if data.header_value is not None:
        webhook.header_value = encrypt(data.header_value) if data.header_value else None
    if data.provider is not None:
        webhook.provider = data.provider.value
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
        has_auth=bool(webhook.header_value),
        header_name=webhook.header_name,
        provider=webhook.provider,
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


def _format_test_payload(provider: str, webhook_name: str) -> dict:
    """Format a test payload based on provider type."""
    if provider == "discord":
        return {
            "embeds": [{
                "title": "🔔 CHAD Test Notification",
                "description": f"Test message from webhook: **{webhook_name}**",
                "color": 0x00FF00,  # Green
                "footer": {"text": "CHAD Alert System"}
            }]
        }
    elif provider == "slack":
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔔 CHAD Test Notification",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Test message from webhook: *{webhook_name}*"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "CHAD Alert System"}
                    ]
                }
            ]
        }
    else:
        return {
            "type": "test",
            "message": "Test notification from CHAD",
            "webhook_name": webhook_name,
        }


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
    if webhook.header_value:
        # Use custom header name or default to Authorization
        header_name = webhook.header_name or "Authorization"
        headers[header_name] = decrypt(webhook.header_value)

    payload = _format_test_payload(webhook.provider, webhook.name)

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
