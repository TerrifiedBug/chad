"""
Notification dispatch service.

Handles sending notifications to configured webhooks based on event type
and alert severity settings.
"""

import logging
from datetime import datetime
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.encryption import decrypt
from app.models.notification_settings import (
    AlertNotificationSetting,
    SystemNotificationSetting,
    Webhook,
)

logger = logging.getLogger(__name__)


async def send_system_notification(
    db: AsyncSession,
    event_type: str,
    payload: dict,
) -> list[dict]:
    """
    Send a system notification to all configured webhooks.

    Args:
        db: Database session
        event_type: One of the SYSTEM_EVENT_TYPES
        payload: Notification payload

    Returns:
        List of results with webhook_id, success, error
    """
    # Get webhooks configured for this event
    result = await db.execute(
        select(SystemNotificationSetting)
        .options(selectinload(SystemNotificationSetting.webhook))
        .where(SystemNotificationSetting.event_type == event_type)
        .where(SystemNotificationSetting.enabled == True)  # noqa: E712
    )
    settings = result.scalars().all()

    results = []
    for setting in settings:
        webhook = setting.webhook
        if not webhook or not webhook.enabled:
            continue

        success, error = await _send_to_webhook(
            webhook,
            {
                "type": "system",
                "event": event_type,
                "timestamp": datetime.now(datetime.UTC).isoformat(),
                **payload,
            },
        )

        results.append(
            {
                "webhook_id": str(webhook.id),
                "webhook_name": webhook.name,
                "success": success,
                "error": error,
            }
        )

    return results


async def send_alert_notification(
    db: AsyncSession,
    alert_id: UUID,
    rule_title: str,
    severity: str,
    matched_log: dict,
    alert_url: str | None = None,
) -> list[dict]:
    """
    Send an alert notification to webhooks configured for this severity.

    Args:
        db: Database session
        alert_id: The alert ID
        rule_title: Title of the rule that triggered
        severity: Alert severity (critical, high, medium, low, informational)
        matched_log: The log document that matched
        alert_url: Optional URL to the alert detail page

    Returns:
        List of results with webhook_id, success, error
    """
    # Get alert notification settings
    result = await db.execute(
        select(AlertNotificationSetting)
        .options(selectinload(AlertNotificationSetting.webhook))
        .where(AlertNotificationSetting.enabled == True)  # noqa: E712
    )
    settings = result.scalars().all()

    payload = {
        "type": "alert",
        "alert_id": str(alert_id),
        "rule_title": rule_title,
        "severity": severity,
        "timestamp": datetime.now(datetime.UTC).isoformat(),
        "matched_log": matched_log,
    }
    if alert_url:
        payload["alert_url"] = alert_url

    results = []
    for setting in settings:
        # Check if this webhook should receive this severity
        if severity not in setting.severities:
            continue

        webhook = setting.webhook
        if not webhook or not webhook.enabled:
            continue

        success, error = await _send_to_webhook(webhook, payload)

        results.append(
            {
                "webhook_id": str(webhook.id),
                "webhook_name": webhook.name,
                "success": success,
                "error": error,
            }
        )

    return results


async def send_health_notification(
    db: AsyncSession,
    level: str,  # "warning" or "critical"
    index_pattern: str,
    condition: str,
    details: dict,
) -> list[dict]:
    """
    Send a health alert notification.

    Args:
        db: Database session
        level: "warning" or "critical"
        index_pattern: The affected index pattern
        condition: Description of the health condition
        details: Additional details

    Returns:
        List of results
    """
    event_type = f"health_{level}"

    return await send_system_notification(
        db,
        event_type,
        {
            "index_pattern": index_pattern,
            "condition": condition,
            "level": level,
            **details,
        },
    )


async def _send_to_webhook(webhook: Webhook, payload: dict) -> tuple[bool, str | None]:
    """Send payload to a webhook. Returns (success, error)."""
    headers = {"Content-Type": "application/json"}
    if webhook.auth_header:
        try:
            headers["Authorization"] = decrypt(webhook.auth_header)
        except Exception as e:
            logger.error(f"Failed to decrypt auth header for webhook {webhook.id}: {e}")
            return False, "Failed to decrypt auth header"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=10.0,
            )
            if response.is_success:
                return True, None
            else:
                return False, f"HTTP {response.status_code}"
    except httpx.TimeoutException:
        return False, "Timeout"
    except Exception as e:
        logger.error(f"Failed to send to webhook {webhook.id}: {e}")
        return False, str(e)
