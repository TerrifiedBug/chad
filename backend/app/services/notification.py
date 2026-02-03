"""
Notification dispatch service.

Handles sending notifications to configured webhooks based on event type
and alert severity settings.
"""

import logging
from datetime import UTC, datetime
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.encryption import decrypt
from app.models.jira_config import JiraConfig
from app.models.notification_settings import (
    AlertNotificationSetting,
    SystemNotificationSetting,
    Webhook,
)
from app.services.jira import JiraAPIError, create_jira_ticket_for_alert
from app.services.system_log import LogCategory, system_log_service

logger = logging.getLogger(__name__)

# Severity colors for Discord (decimal format)
SEVERITY_COLORS = {
    "critical": 0xFF0000,    # Red
    "high": 0xFF8C00,        # Dark Orange
    "medium": 0xFFD700,      # Gold
    "low": 0x4169E1,         # Royal Blue
    "informational": 0x808080,  # Gray
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


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
                "timestamp": datetime.now(UTC).isoformat(),
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
    Send an alert notification to webhooks and Jira (if configured) for this severity.

    Args:
        db: Database session
        alert_id: The alert ID
        rule_title: Title of the rule that triggered
        severity: Alert severity (critical, high, medium, low, informational)
        matched_log: The log document that matched
        alert_url: Optional URL to the alert detail page

    Returns:
        List of results with webhook_id/jira, success, error
    """
    results = []

    # Send to webhooks
    webhook_results = await _send_alert_to_webhooks(
        db, alert_id, rule_title, severity, matched_log, alert_url
    )
    results.extend(webhook_results)

    # Send to Jira if configured
    jira_result = await _send_alert_to_jira(
        db, alert_id, rule_title, severity, matched_log, alert_url
    )
    if jira_result:
        results.append(jira_result)

    return results


async def _send_alert_to_webhooks(
    db: AsyncSession,
    alert_id: UUID,
    rule_title: str,
    severity: str,
    matched_log: dict,
    alert_url: str | None = None,
) -> list[dict]:
    """Send alert to configured webhooks."""
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
        "timestamp": datetime.now(UTC).isoformat(),
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


async def _send_alert_to_jira(
    db: AsyncSession,
    alert_id: UUID,
    rule_title: str,
    severity: str,
    matched_log: dict,
    alert_url: str | None = None,
) -> dict | None:
    """Send alert to Jira if configured for this severity."""
    # Get Jira config
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config or not config.is_enabled:
        return None

    # Check if this severity should create a Jira ticket
    if not config.alert_severities or severity not in config.alert_severities:
        return None

    try:
        issue = await create_jira_ticket_for_alert(
            config=config,
            alert_id=str(alert_id),
            rule_title=rule_title,
            severity=severity,
            matched_log=matched_log,
            alert_url=alert_url,
        )
        logger.info("Created Jira issue %s for alert %s", issue.get('key'), alert_id)
        return {
            "destination": "jira",
            "success": True,
            "issue_key": issue.get("key"),
            "error": None,
        }
    except JiraAPIError as e:
        # Log error type only to prevent log injection from external API responses
        logger.error("Failed to create Jira issue for alert %s: JiraAPIError", alert_id)
        await system_log_service.log_error(
            db,
            category=LogCategory.INTEGRATIONS,
            service="notification",
            message="Failed to create Jira issue for alert",
            details={
                "alert_id": str(alert_id),
                "rule_title": rule_title,
                "severity": severity,
                "error": e.message,
                "error_type": "JiraAPIError",
            },
        )
        return {
            "destination": "jira",
            "success": False,
            "error": e.message,
        }
    except Exception as e:
        # Log error type only to prevent log injection
        logger.error("Unexpected error creating Jira issue for alert %s: %s", alert_id, type(e).__name__)
        await system_log_service.log_error(
            db,
            category=LogCategory.INTEGRATIONS,
            service="notification",
            message="Unexpected error creating Jira issue for alert",
            details={
                "alert_id": str(alert_id),
                "rule_title": rule_title,
                "severity": severity,
                "error": str(e),
                "error_type": type(e).__name__,
            },
        )
        return {
            "destination": "jira",
            "success": False,
            "error": str(e),
        }


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


def _format_discord_payload(payload: dict) -> dict:
    """Format payload for Discord webhook."""
    # System notification
    if payload.get("type") == "system":
        event = payload.get("event", "unknown")
        event_display = event.replace("_", " ").title()
        return {
            "embeds": [{
                "title": f"🔔 {event_display}",
                "description": _build_system_description(payload),
                "color": 0x5865F2,  # Discord blurple
                "timestamp": payload.get("timestamp"),
                "footer": {"text": "CHAD Alert System"}
            }]
        }

    # Alert notification
    severity = payload.get("severity", "medium")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])
    alert_url = payload.get("alert_url")

    fields = [
        {"name": "Alert ID", "value": f"`{payload.get('alert_id', 'N/A')}`", "inline": True},
        {"name": "Severity", "value": severity.upper(), "inline": True},
    ]

    # Add clickable link to alert if URL is available
    if alert_url:
        fields.append({"name": "View Alert", "value": f"[Open in CHAD]({alert_url})", "inline": False})

    return {
        "embeds": [{
            "title": f"{emoji} {payload.get('rule_title', 'Alert')}",
            "description": f"A **{severity.upper()}** severity alert has been triggered.",
            "color": color,
            "fields": fields,
            "timestamp": payload.get("timestamp"),
            "footer": {"text": "CHAD Alert System"}
        }]
    }


def _format_slack_payload(payload: dict) -> dict:
    """Format payload for Slack webhook."""
    # System notification
    if payload.get("type") == "system":
        event = payload.get("event", "unknown")
        event_display = event.replace("_", " ").title()
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🔔 {event_display}", "emoji": True}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": _build_system_description(payload)}
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "CHAD Alert System"}]
                }
            ]
        }

    # Alert notification
    severity = payload.get("severity", "medium")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    alert_url = payload.get("alert_url")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {payload.get('rule_title', 'Alert')}", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Alert ID:*\n`{payload.get('alert_id', 'N/A')}`"},
            ]
        },
    ]

    # Add button to view alert if URL is available
    if alert_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Alert", "emoji": True},
                "url": alert_url,
                "style": "primary"
            }]
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "CHAD Alert System"}]
    })

    return {"blocks": blocks}


def _build_system_description(payload: dict) -> str:
    """Build a description string for system notifications."""
    event = payload.get("event", "")
    parts = []

    if event == "user_locked":
        parts.append(f"User `{payload.get('email', 'unknown')}` has been locked out")
        if payload.get("ip_address"):
            parts.append(f"IP: {payload['ip_address']}")
    elif event == "sigmahq_sync_complete":
        parts.append(f"SigmaHQ sync completed: {payload.get('message', '')}")
        if payload.get("rule_count"):
            parts.append(f"Rules: {payload['rule_count']}")
    elif event == "attack_sync_complete":
        parts.append(f"ATT&CK sync completed: {payload.get('message', '')}")
        if payload.get("techniques_updated"):
            parts.append(f"Techniques updated: {payload['techniques_updated']}")
    elif event == "sigmahq_new_rules":
        parts.append(f"New rules available: {payload.get('count', 0)} from {payload.get('source', 'unknown')}")
    elif event == "sync_failed":
        parts.append(f"Sync failed: {payload.get('sync_type', 'unknown')}")
        if payload.get("error"):
            parts.append(f"Error: {payload['error']}")
    elif "health" in event:
        condition = payload.get("condition", "")
        if payload.get("index_pattern"):
            parts.append(f"{condition} (Index: {payload['index_pattern']})")
        else:
            parts.append(condition)
    else:
        parts.append(str(payload))

    return "\n".join(parts)


def _format_payload_for_provider(provider: str, payload: dict) -> dict:
    """Format payload based on webhook provider."""
    if provider == "discord":
        return _format_discord_payload(payload)
    elif provider == "slack":
        return _format_slack_payload(payload)
    else:
        return payload


async def _send_to_webhook(webhook: Webhook, payload: dict) -> tuple[bool, str | None]:
    """Send payload to a webhook. Returns (success, error)."""
    headers = {"Content-Type": "application/json"}
    if webhook.header_value:
        try:
            # Use custom header name or default to Authorization
            header_name = webhook.header_name or "Authorization"
            headers[header_name] = decrypt(webhook.header_value)
        except Exception as e:
            logger.error("Failed to decrypt header value for webhook %s: %s", webhook.id, e)
            return False, "Failed to decrypt header value"

    # Format payload based on provider
    formatted_payload = _format_payload_for_provider(webhook.provider, payload)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook.url,
                json=formatted_payload,
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
        logger.error("Failed to send to webhook %s: %s", webhook.id, e)
        return False, str(e)
