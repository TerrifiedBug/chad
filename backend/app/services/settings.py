"""Settings service for retrieving configuration from database."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.setting import Setting

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
    """Get configured APP_URL or None."""
    setting = await get_setting(db, "app_url")
    if setting and setting.get("url"):
        return setting["url"]
    return None
