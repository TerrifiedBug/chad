"""Queue settings service."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.queue import QueueSettings
from app.services.settings import get_setting


async def get_queue_settings(db: AsyncSession) -> QueueSettings:
    """
    Get queue settings from database with defaults.

    Returns QueueSettings with values from DB merged with defaults.
    """
    stored = await get_setting(db, "queue_settings") or {}

    return QueueSettings(
        max_queue_size=stored.get("max_queue_size", 100000),
        warning_threshold=stored.get("warning_threshold", 10000),
        critical_threshold=stored.get("critical_threshold", 50000),
        backpressure_mode=stored.get("backpressure_mode", "drop"),
        batch_size=stored.get("batch_size", 500),
        batch_timeout_seconds=stored.get("batch_timeout_seconds", 5),
        message_ttl_seconds=stored.get("message_ttl_seconds", 1800),
    )
