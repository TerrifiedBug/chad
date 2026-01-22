"""
Webhook notification service.

Sends alert notifications to configured webhook URLs.
Supports global webhooks (all alerts) and per-severity webhooks.
"""

from datetime import datetime, timezone
from typing import Any

import httpx
from opensearchpy import OpenSearch
from sqlalchemy import select


class WebhookService:
    @staticmethod
    async def send_notifications(
        os_client: OpenSearch,
        alerts: list[dict[str, Any]],
    ) -> None:
        """Send webhook notifications for a batch of alerts."""
        # Get webhook config from settings
        webhook_url = await WebhookService._get_webhook_url(os_client)
        if not webhook_url:
            return

        # Build payload
        payload = {
            "event": "alerts.created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alerts": [
                {
                    "alert_id": alert["alert_id"],
                    "rule_id": alert["rule_id"],
                    "rule_title": alert["rule_title"],
                    "severity": alert["severity"],
                    "tags": alert.get("tags", []),
                    "created_at": alert["created_at"],
                }
                for alert in alerts
            ],
            "summary": {
                "total": len(alerts),
                "by_severity": WebhookService._count_by_severity(alerts),
            },
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.post(webhook_url, json=payload)
                if response.status_code >= 400:
                    print(f"Webhook failed: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"Webhook error: {e}")

    @staticmethod
    async def _get_webhook_url(os_client: OpenSearch) -> str | None:
        """Get global webhook URL from database settings."""
        # Import here to avoid circular imports
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        from app.models.setting import Setting
        import os

        db_url = (
            f"postgresql+asyncpg://{os.environ.get('POSTGRES_USER', 'chad')}:"
            f"{os.environ.get('POSTGRES_PASSWORD', 'devpassword')}@"
            f"{os.environ.get('POSTGRES_HOST', 'postgres')}:"
            f"{os.environ.get('POSTGRES_PORT', '5432')}/"
            f"{os.environ.get('POSTGRES_DB', 'chad')}"
        )

        engine = create_async_engine(db_url)
        async_session = async_sessionmaker(engine, class_=AsyncSession)

        try:
            async with async_session() as session:
                result = await session.execute(
                    select(Setting).where(Setting.key == "webhooks")
                )
                setting = result.scalar_one_or_none()

                if setting and setting.value:
                    return setting.value.get("global_url")
                return None
        except Exception:
            return None
        finally:
            await engine.dispose()

    @staticmethod
    def _count_by_severity(alerts: list[dict[str, Any]]) -> dict[str, int]:
        """Count alerts by severity level."""
        counts: dict[str, int] = {}
        for alert in alerts:
            sev = alert.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
