"""
Webhook notification service.

Sends alert notifications to configured webhook URLs.
Supports multiple providers with provider-specific payload formatting:
- generic: Raw alert JSON
- discord: Discord embed format
- slack: Slack block format
"""

import asyncio
import logging
import os
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models.setting import Setting

logger = logging.getLogger(__name__)

# Severity colors for Discord (decimal format)
SEVERITY_COLORS = {
    "critical": 0xFF0000,    # Red
    "high": 0xFF8C00,        # Dark Orange
    "medium": 0xFFD700,      # Gold
    "low": 0x4169E1,         # Royal Blue
    "informational": 0x808080,  # Gray
}

# Severity order for filtering
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def should_send_webhook(alert_severity: str, filter_severity: str) -> bool:
    """Check if alert severity meets the minimum filter threshold."""
    if filter_severity == "all":
        return True

    alert_idx = SEVERITY_ORDER.index(alert_severity) if alert_severity in SEVERITY_ORDER else 0
    filter_idx = SEVERITY_ORDER.index(filter_severity) if filter_severity in SEVERITY_ORDER else 0

    return alert_idx >= filter_idx


def format_generic_payload(alert: dict[str, Any], alert_url: str | None = None) -> dict[str, Any]:
    """Format payload for generic webhook - structured alert data."""
    alert_data = {
        "alert_id": alert.get("alert_id"),
        "rule_id": alert.get("rule_id"),
        "rule_title": alert.get("rule_title"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "tags": alert.get("tags", []),
        "created_at": alert.get("created_at"),
    }

    # Include alert URL if available
    if alert_url:
        alert_data["alert_url"] = alert_url

    return {
        "event": "alert.created",
        "timestamp": datetime.now(UTC).isoformat(),
        "alert": alert_data,
    }


def format_discord_payload(alert: dict[str, Any], alert_url: str | None = None) -> dict[str, Any]:
    """Format payload for Discord webhook."""
    severity = alert.get("severity", "medium")
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])

    # Emoji for severity
    emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "informational": "⚪",
    }.get(severity, "⚪")

    fields = [
        {
            "name": "Alert ID",
            "value": f"`{alert.get('alert_id', 'N/A')}`",
            "inline": True,
        },
        {
            "name": "Status",
            "value": alert.get("status", "new").title(),
            "inline": True,
        },
        {
            "name": "Tags",
            "value": ", ".join(alert.get("tags", [])) or "None",
            "inline": False,
        },
    ]

    # Add link field if alert URL is available
    if alert_url:
        fields.append({
            "name": "View Alert",
            "value": f"[Open in CHAD]({alert_url})",
            "inline": False,
        })

    return {
        "embeds": [{
            "title": f"{emoji} {alert.get('rule_title', 'Alert')}",
            "description": f"A **{severity.upper()}** severity alert has been triggered.",
            "color": color,
            "fields": fields,
            "timestamp": alert.get("created_at", datetime.utcnow().isoformat()),
            "footer": {
                "text": "CHAD Alert System"
            }
        }]
    }


def format_slack_payload(alert: dict[str, Any], alert_url: str | None = None) -> dict[str, Any]:
    """Format payload for Slack webhook."""
    severity = alert.get("severity", "medium")
    emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "informational": "⚪",
    }.get(severity, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {alert.get('rule_title', 'Alert')}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n{severity.upper()}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n{alert.get('status', 'new').title()}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Alert ID:*\n`{alert.get('alert_id', 'N/A')}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Tags:*\n{', '.join(alert.get('tags', [])) or 'None'}"
                }
            ]
        },
    ]

    # Add button to view alert if URL is available
    if alert_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Alert in CHAD",
                        "emoji": True
                    },
                    "url": alert_url,
                    "style": "primary"
                }
            ]
        })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"CHAD Alert System • {alert.get('created_at', 'Unknown time')}"
            }
        ]
    })

    return {"blocks": blocks}


FORMATTERS = {
    "generic": format_generic_payload,
    "discord": format_discord_payload,
    "slack": format_slack_payload,
}


async def send_webhook(
    url: str,
    provider: str,
    alert: dict[str, Any],
    timeout: float = 10.0,
    alert_url: str | None = None,
) -> bool:
    """
    Send alert to a webhook endpoint.

    Args:
        url: Webhook URL
        provider: Provider type (generic, discord, slack)
        alert: Alert data
        timeout: Request timeout in seconds
        alert_url: Optional URL to view the alert in CHAD

    Returns:
        True if successful, False otherwise
    """
    formatter = FORMATTERS.get(provider, format_generic_payload)
    payload = formatter(alert, alert_url)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code >= 400:
                logger.error(
                    "Webhook failed: %s returned %s: %s",
                    url,
                    response.status_code,
                    response.text[:200],
                )
                return False

            return True

    except httpx.TimeoutException:
        logger.error("Webhook timeout: %s", url)
        return False
    except Exception as e:
        logger.error("Webhook error: %s - %s", url, e)
        return False


def _get_db_url() -> str:
    """Build database URL from environment variables."""
    return (
        f"postgresql+asyncpg://{os.environ.get('POSTGRES_USER', 'chad')}:"
        f"{os.environ.get('POSTGRES_PASSWORD', 'devpassword')}@"
        f"{os.environ.get('POSTGRES_HOST', 'postgres')}:"
        f"{os.environ.get('POSTGRES_PORT', '5432')}/"
        f"{os.environ.get('POSTGRES_DB', 'chad')}"
    )


async def get_webhook_config() -> dict[str, Any] | None:
    """Get webhook configuration from database settings."""
    engine = create_async_engine(_get_db_url())
    async_session_factory = async_sessionmaker(engine, class_=AsyncSession)

    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(Setting).where(Setting.key == "webhooks")
            )
            setting = result.scalar_one_or_none()

            if setting and setting.value:
                return setting.value
            return None
    except Exception as e:
        logger.error("Failed to get webhook config: %s", e)
        return None
    finally:
        await engine.dispose()


async def send_alert_to_webhooks(alert: dict[str, Any]) -> dict[str, bool]:
    """
    Send alert to all configured and enabled webhooks.

    Args:
        alert: Alert data

    Returns:
        Dict mapping webhook names to success status
    """
    config = await get_webhook_config()

    if not config or not config.get("enabled"):
        return {}

    webhooks = config.get("webhooks", [])

    # Support legacy single webhook format
    if not webhooks and config.get("global_url"):
        webhooks = [{
            "name": "Default",
            "url": config["global_url"],
            "provider": "generic",
            "severity_filter": "all",
            "enabled": True,
        }]

    if not webhooks:
        return {}

    # Build alert URL if APP_URL is configured
    from app.core.config import settings
    app_url = settings.APP_URL
    alert_url = None
    if app_url and alert.get("alert_id"):
        alert_url = f"{app_url}/alerts/{alert['alert_id']}"

    alert_severity = alert.get("severity", "medium")
    results = {}
    tasks = []

    for webhook in webhooks:
        if not webhook.get("enabled"):
            continue

        # Check severity filter
        severity_filter = webhook.get("severity_filter", "all")
        if not should_send_webhook(alert_severity, severity_filter):
            continue

        name = webhook.get("name", "Unnamed")
        url = webhook.get("url", "")
        provider = webhook.get("provider", "generic")

        if not url:
            continue

        tasks.append((name, send_webhook(url, provider, alert, alert_url=alert_url)))

    # Send all webhooks concurrently
    if tasks:
        webhook_results = await asyncio.gather(
            *[task for _, task in tasks],
            return_exceptions=True
        )

        for (name, _), result in zip(tasks, webhook_results):
            if isinstance(result, Exception):
                logger.error("Webhook %s exception: %s", name, result)
                results[name] = False
            else:
                results[name] = result

    return results


# Legacy class for backwards compatibility
class WebhookService:
    @staticmethod
    async def send_notifications(
        os_client: Any,
        alerts: list[dict[str, Any]],
    ) -> None:
        """Send webhook notifications for a batch of alerts."""
        for alert in alerts:
            await send_alert_to_webhooks(alert)
