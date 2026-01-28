"""
Rate limiting service for login protection.

Tracks failed login attempts per account and enforces lockout policy.
"""

from datetime import datetime, timedelta
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.login_attempt import LoginAttempt
from app.services.settings import get_setting, RATE_LIMIT_DEFAULTS


async def get_rate_limit_settings(db: AsyncSession) -> dict:
    """Get rate limiting configuration from settings."""
    settings = await get_setting(db, "rate_limit")

    if settings:
        return {
            "enabled": settings.get("enabled", RATE_LIMIT_DEFAULTS["rate_limit_enabled"]),
            "max_attempts": settings.get("max_attempts", RATE_LIMIT_DEFAULTS["rate_limit_max_attempts"]),
            "lockout_minutes": settings.get("lockout_minutes", RATE_LIMIT_DEFAULTS["rate_limit_lockout_minutes"]),
        }

    return {
        "enabled": RATE_LIMIT_DEFAULTS["rate_limit_enabled"],
        "max_attempts": RATE_LIMIT_DEFAULTS["rate_limit_max_attempts"],
        "lockout_minutes": RATE_LIMIT_DEFAULTS["rate_limit_lockout_minutes"],
    }


async def record_failed_attempt(
    db: AsyncSession,
    email: str,
    ip_address: str,
) -> None:
    """Record a failed login attempt."""
    attempt = LoginAttempt(
        email=email.lower(),
        ip_address=ip_address,
    )
    db.add(attempt)
    await db.commit()


async def get_failed_attempt_count(
    db: AsyncSession,
    email: str,
    window_minutes: int,
) -> int:
    """Count failed attempts for an account within the time window."""
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == email.lower(),
            LoginAttempt.attempted_at >= cutoff,
        )
    )
    return result.scalar() or 0


async def is_account_locked(db: AsyncSession, email: str) -> tuple[bool, int | None]:
    """
    Check if account is locked due to too many failed attempts.

    Returns:
        (is_locked, remaining_minutes) - remaining_minutes is None if not locked
    """
    settings = await get_rate_limit_settings(db)

    if not settings["enabled"]:
        return False, None

    count = await get_failed_attempt_count(
        db, email, settings["lockout_minutes"]
    )

    if count >= settings["max_attempts"]:
        # Find the oldest failed attempt in the window to calculate remaining time
        cutoff = datetime.utcnow() - timedelta(minutes=settings["lockout_minutes"])
        result = await db.execute(
            select(LoginAttempt).where(
                LoginAttempt.email == email.lower(),
                LoginAttempt.attempted_at >= cutoff,
            ).order_by(LoginAttempt.attempted_at.asc()).limit(1)
        )
        oldest_attempt = result.scalar_one_or_none()

        if oldest_attempt:
            # Calculate minutes elapsed since the first failed attempt
            elapsed = (datetime.utcnow() - oldest_attempt.attempted_at.replace(tzinfo=None)).total_seconds() / 60
            remaining = settings["lockout_minutes"] - int(elapsed)
            return True, max(0, remaining)

        # Fallback if we can't find the oldest attempt
        return True, settings["lockout_minutes"]

    return False, None


async def clear_failed_attempts(db: AsyncSession, email: str) -> None:
    """Clear failed attempts for an account after successful login."""
    await db.execute(
        delete(LoginAttempt).where(LoginAttempt.email == email.lower())
    )
    await db.commit()


async def cleanup_old_attempts(db: AsyncSession, older_than_minutes: int = 60) -> int:
    """Remove login attempts older than specified minutes. Returns count deleted."""
    cutoff = datetime.utcnow() - timedelta(minutes=older_than_minutes)
    result = await db.execute(
        delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff)
    )
    await db.commit()
    return result.rowcount
