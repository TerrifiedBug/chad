"""SCIM 2.0 service helpers.

Owns SCIM config in the ``scim`` Setting key:
  - scim.enabled        : SCIM is off by default.
  - scim.bearer_token   : Fernet-encrypted bearer token (compared constant-time).

Plus User<->SCIM resource mapping and the coexistence guards that stop SCIM from
ever deactivating a LOCAL/SSO user or the last active admin.
"""

import hmac
import logging
import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt, encrypt
from app.models.setting import Setting
from app.models.user import ProvisionedVia, User, UserRole
from app.services.settings import get_setting

logger = logging.getLogger(__name__)

SCIM_SETTING_KEY = "scim"

# Lock-source marker distinct from admin/brute-force locks, so SCIM-deactivated
# users are attributable and re-activatable without confusing other lock logic.
SCIM_DEACTIVATION_SOURCE = "scim"


async def get_scim_config(db: AsyncSession) -> dict:
    """Return the raw scim Setting dict (or empty if unset)."""
    return await get_setting(db, SCIM_SETTING_KEY) or {}


async def is_scim_enabled(db: AsyncSession) -> bool:
    cfg = await get_scim_config(db)
    return bool(cfg.get("enabled"))


async def get_scim_token_plaintext(db: AsyncSession) -> str | None:
    """Decrypt and return the stored bearer token, or None if not configured."""
    cfg = await get_scim_config(db)
    enc = cfg.get("bearer_token")
    if not enc:
        return None
    try:
        return decrypt(enc)
    except Exception:
        # Token is unreadable (wrong key / corrupt ciphertext). Return None so the
        # constant-time compare fails closed — NEVER return the stored ciphertext
        # as the expected token (it must never become an accepted credential).
        logger.warning("SCIM bearer token could not be decrypted; treating as unset")
        return None


def verify_scim_token(provided: str, expected: str | None) -> bool:
    """Constant-time bearer comparison (hmac.compare_digest)."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


async def generate_scim_token(db: AsyncSession) -> str:
    """Generate a new 64-hex bearer token, store it ENCRYPTED, return plaintext once."""
    token = secrets.token_hex(32)  # 64 hex chars
    cfg = await get_scim_config(db)

    result = await db.execute(select(Setting).where(Setting.key == SCIM_SETTING_KEY))
    setting = result.scalar_one_or_none()
    new_value = dict(cfg)
    new_value["bearer_token"] = encrypt(token)
    # Generating a token does not implicitly enable SCIM.
    new_value.setdefault("enabled", False)

    if setting:
        setting.value = new_value
    else:
        setting = Setting(key=SCIM_SETTING_KEY, value=new_value)
        db.add(setting)
    # Caller commits.
    return token


async def set_scim_enabled(db: AsyncSession, enabled: bool) -> None:
    cfg = await get_scim_config(db)
    result = await db.execute(select(Setting).where(Setting.key == SCIM_SETTING_KEY))
    setting = result.scalar_one_or_none()
    new_value = dict(cfg)
    new_value["enabled"] = bool(enabled)
    if setting:
        setting.value = new_value
    else:
        setting = Setting(key=SCIM_SETTING_KEY, value=new_value)
        db.add(setting)


async def count_active_admins(db: AsyncSession, exclude_user_id=None) -> int:
    """Count active admins, optionally excluding one user id."""
    stmt = select(func.count()).select_from(User).where(
        User.role == UserRole.ADMIN, User.is_active.is_(True)
    )
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    result = await db.execute(stmt)
    return int(result.scalar() or 0)


def is_scim_managed(user: User) -> bool:
    """Whether SCIM provisioned this user (and may therefore mutate/deactivate it)."""
    return user.provisioned_via == ProvisionedVia.SCIM.value


async def can_scim_deactivate(db: AsyncSession, user: User) -> tuple[bool, str]:
    """Coexistence guard: may SCIM deactivate/deprovision ``user``?

    Refuses (no false alert) when the user is LOCAL/SSO-provisioned or is the
    last active admin.

    Returns (allowed, reason).
    """
    if not is_scim_managed(user):
        return False, "User is not SCIM-provisioned and cannot be modified via SCIM"
    if user.role == UserRole.ADMIN and user.is_active:
        remaining = await count_active_admins(db, exclude_user_id=user.id)
        if remaining < 1:
            return False, "Cannot deactivate the last active admin"
    return True, ""
