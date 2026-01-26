"""Settings service for retrieving configuration from database."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.setting import Setting

logger = logging.getLogger(__name__)

# Default settings for rate limiting
RATE_LIMIT_DEFAULTS = {
    "rate_limit_enabled": True,
    "rate_limit_max_attempts": 5,
    "rate_limit_lockout_minutes": 15,
}


async def get_setting(db: AsyncSession, key: str) -> dict | None:
    """Get a setting value by key."""
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()
    return setting.value if setting else None


async def set_setting(db: AsyncSession, key: str, value: dict) -> Setting:
    """Set a setting value by key (create or update)."""
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()

    if setting:
        setting.value = value
    else:
        setting = Setting(key=key, value=value)
        db.add(setting)

    await db.commit()
    await db.refresh(setting)
    return setting


async def get_app_url(db: AsyncSession) -> str | None:
    """
    Get APP_URL from environment variable.

    Returns:
        APP_URL string or None if not configured
    """
    from app.core.config import settings

    if settings.APP_URL:
        logger.info(f"Using APP_URL from environment: {settings.APP_URL}")
        return settings.APP_URL

    logger.debug("APP_URL not configured, allowing localhost only")
    return None
