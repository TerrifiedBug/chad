import logging
import uuid
from datetime import timedelta
from typing import Annotated
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    block_in_delegated_mode,
    get_current_user,
    require_admin,
    require_permission_dep,
)
from app.core.config import settings as app_settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.session import get_db
from app.models.sso_provider import SSOProvider
from app.models.user import AuthMethod, ProvisionedVia, User, UserRole
from app.schemas.auth import LoginRequest, SetupRequest, TokenResponse
from app.schemas.sso import SSOEnforcementResponse, SSOEnforcementUpdate
from app.schemas.totp import (
    TwoFactorDisableRequest,
    TwoFactorLoginRequest,
    TwoFactorSetupResponse,
    TwoFactorVerifyRequest,
    TwoFactorVerifyResponse,
)
from app.services.audit import audit_log
from app.services.notification import send_system_notification
from app.services.rate_limit import (
    clear_failed_attempts,
    is_account_locked,
    record_failed_attempt,
)
from app.services.settings import get_app_url, get_setting, set_setting
from app.services.sso_providers import build_provider_client, get_provider_client
from app.services.sso_reconcile import reconcile_user_team_memberships
from app.services.totp import (
    generate_backup_codes,
    generate_qr_uri,
    generate_totp_secret,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth client instance
oauth = OAuth()

# Default session timeout in minutes (8 hours)
DEFAULT_SESSION_TIMEOUT_MINUTES = 480

# 2FA token types
TOKEN_TYPE_SETUP = "setup"
TOKEN_TYPE_LOGIN = "login"


def validate_password_complexity(
    password: str,
    user_email: str | None = None,
) -> tuple[bool, str]:
    """
    Validate password meets strong complexity requirements.

    Requirements (following NIST guidelines):
    - At least 12 characters (increased from 8 for better security)
    - Maximum 128 characters (prevents DoS)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    - Cannot contain user's email (if provided)

    Args:
        password: The password to validate
        user_email: User's email address (optional, for additional validation)

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Length requirements
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if len(password) > 128:
        return False, "Password must not exceed 128 characters"

    # Check for user information in password
    if user_email:
        email_username = user_email.split('@')[0].lower()
        if email_username and len(email_username) >= 3 and email_username in password.lower():
            return False, "Password cannot contain your email username"

    # Character complexity requirements
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter (A-Z)"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter (a-z)"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number (0-9)"

    special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:',.<>?/`~)"

    # Check for common patterns (basic check)
    password_lower = password.lower()

    # Common sequential patterns
    sequential_patterns = [
        "123456", "234567", "345678", "456789", "567890",
        "abcde", "bcdef", "cdefg", "defgh", "efghi",
        "qwerty", "asdfgh", "zxcvbn",
    ]
    for pattern in sequential_patterns:
        if pattern in password_lower:
            return False, f"Password cannot contain common patterns like '{pattern}'"

    # Common repeated characters
    if any(char * 4 in password_lower for char in "0123456789abcdefghijklmnopqrstuvwxyz"):
        return False, "Password cannot contain repeated characters (e.g., 'aaaa' or '1111')"

    # Common passwords (basic list - in production, use zxcvbn or haveibeenpwned API)
    common_passwords = {
        "password", "password123", "password1",
        "qwerty", "qwerty123", "qwerty1",
        "letmein", "letmein123",
        "admin", "admin123", "admin1",
        "welcome", "welcome123", "welcome1",
        "12345678", "123456789", "1234567890",
        "abc123", "abc12345",
    }
    if password_lower in common_passwords:
        return False, "Password is too common. Please choose a more secure password"

    return True, ""


def _get_role_from_claims(userinfo: dict, sso_config: dict) -> UserRole | None:
    """
    Extract and map role from IdP claims.

    Returns the mapped role or None if role mapping is not configured
    or the claim doesn't match any configured values.
    """
    if not sso_config.get("role_mapping_enabled"):
        return None

    role_claim = sso_config.get("role_claim")
    if not role_claim:
        return None

    # Get claim value - could be string or list
    claim_value = userinfo.get(role_claim)
    if claim_value is None:
        return None

    # Normalize to list for consistent processing
    claim_values = claim_value if isinstance(claim_value, list) else [claim_value]
    claim_values_lower = [str(v).lower() for v in claim_values]

    # Check admin values first (highest priority)
    admin_values = sso_config.get("admin_values", "")
    if admin_values:
        admin_list = [v.strip().lower() for v in admin_values.split(",") if v.strip()]
        if any(v in claim_values_lower for v in admin_list):
            return UserRole.ADMIN

    # Check analyst values
    analyst_values = sso_config.get("analyst_values", "")
    if analyst_values:
        analyst_list = [v.strip().lower() for v in analyst_values.split(",") if v.strip()]
        if any(v in claim_values_lower for v in analyst_list):
            return UserRole.ANALYST

    # Check viewer values
    viewer_values = sso_config.get("viewer_values", "")
    if viewer_values:
        viewer_list = [v.strip().lower() for v in viewer_values.split(",") if v.strip()]
        if any(v in claim_values_lower for v in viewer_list):
            return UserRole.VIEWER

    # No match found
    return None


async def create_token_with_dynamic_timeout(user_id: str, db: AsyncSession, token_version: int = 0) -> str:
    """Create JWT with configurable expiration from settings."""
    session_config = await get_setting(db, "session")
    timeout_minutes = (
        session_config.get("timeout_minutes", DEFAULT_SESSION_TIMEOUT_MINUTES)
        if session_config
        else DEFAULT_SESSION_TIMEOUT_MINUTES
    )
    expires_delta = timedelta(minutes=timeout_minutes)
    return create_access_token(data={"sub": user_id}, expires_delta=expires_delta, token_version=token_version)


@router.get("/setup-status")
async def get_setup_status(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(func.count()).select_from(User))
    user_count = result.scalar()
    return {
        # In delegated mode VF owns account setup/provisioning entirely, so
        # the CHAD setup wizard is meaningless (and would deadlock the
        # frontend at cold start if left gated on user_count).
        "setup_completed": app_settings.CHAD_DELEGATED_AUTH or user_count > 0,
        "chad_delegated_auth": app_settings.CHAD_DELEGATED_AUTH,
    }


@router.post("/setup", response_model=TokenResponse, dependencies=[Depends(block_in_delegated_mode)])
async def initial_setup(
    request: SetupRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Check if setup already completed
    result = await db.execute(select(func.count()).select_from(User))
    if result.scalar() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setup already completed",
        )

    # Validate password complexity (pass email for additional validation)
    is_valid, error_msg = validate_password_complexity(
        request.admin_password,
        user_email=request.admin_email,
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # Create admin user
    admin = User(
        email=request.admin_email,
        password_hash=get_password_hash(request.admin_password),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin)

    await db.commit()
    await db.refresh(admin)

    # Generate token with dynamic timeout
    access_token = await create_token_with_dynamic_timeout(str(admin.id), db, admin.token_version)
    return TokenResponse(access_token=access_token)


@router.post("/login", dependencies=[Depends(block_in_delegated_mode)])
async def login(
    request: LoginRequest,
    http_request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Normalize email to lowercase
    email = request.email.lower()
    ip_address = get_client_ip(http_request)

    # Check if account is locked due to too many failed attempts
    locked, lockout_minutes = await is_account_locked(db, email)
    if locked:
        await audit_log(
            db,
            None,
            "auth.lockout_login_attempt",
            "user",
            None,
            {"email": email},
            ip_address=ip_address,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Account temporarily locked due to too many failed login attempts. "
                f"Try again in {lockout_minutes} minutes."
            ),
        )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Check if user exists
    if user is None:
        # Record failed attempt
        await record_failed_attempt(db, email, ip_address)
        await audit_log(
            db,
            None,
            "auth.login_failed",
            "user",
            None,
            {"email": email, "reason": "user_not_found"},
            ip_address=ip_address,
        )

        # Check if this attempt triggered a lockout
        locked_now, _ = await is_account_locked(db, email)
        if locked_now:
            await audit_log(
                db,
                None,
                "auth.lockout",
                "user",
                None,
                {"email": email},
                ip_address=ip_address,
            )
            # Send lockout notification
            await send_system_notification(
                db,
                "user_locked",
                {"email": email, "ip_address": ip_address},
            )

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check if user is SSO-only (no password hash)
    if user.password_hash is None:
        # Don't record failed attempts or check lockout for SSO users
        # (they have no password to brute force, and we don't want to lock them out of SSO)
        await audit_log(
            db,
            None,
            "auth.login_failed",
            "user",
            None,
            {"email": email, "reason": "sso_only_user_attempted_local_login"},
            ip_address=ip_address,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account uses SSO only. Please login with your SSO provider.",
        )

    # Check if user is SSO-only (redundant check, but kept for safety)
    if user.auth_method == AuthMethod.SSO:
        # Don't record failed attempts or check lockout for SSO users
        await audit_log(
            db,
            user.id,
            "auth.login_failed",
            "user",
            str(user.id),
            {"email": email, "reason": "sso_only_user_attempted_local_login"},
            ip_address=ip_address,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account uses SSO only. Please login with your SSO provider.",
        )

    # Verify password
    if not verify_password(request.password, user.password_hash):
        # Record failed attempt
        await record_failed_attempt(db, email, ip_address)
        await audit_log(
            db,
            user.id,
            "auth.login_failed",
            "user",
            str(user.id),
            {"email": email, "reason": "invalid_credentials"},
            ip_address=ip_address,
        )

        # Check if this attempt triggered a lockout
        locked_now, _ = await is_account_locked(db, email)
        if locked_now:
            await audit_log(
                db,
                user.id,
                "auth.lockout",
                "user",
                str(user.id),
                {"email": email},
                ip_address=ip_address,
            )
            # Send lockout notification
            await send_system_notification(
                db,
                "user_locked",
                {"email": email, "ip_address": ip_address},
            )

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    # Check if 2FA is enabled
    if user.totp_enabled:
        import secrets

        temp_token = secrets.token_urlsafe(32)
        # Store in database with 10-minute expiration
        from app.models.two_factor_token import TwoFactorToken
        await TwoFactorToken.create_token(
            db,
            user_id=temp_token,  # Use temp_token as key (maps to actual user_id)
            token_type=TOKEN_TYPE_LOGIN,
            token_data=str(user.id),
            expires_minutes=10,
        )
        await clear_failed_attempts(db, email)
        await db.commit()
        return {"requires_2fa": True, "2fa_token": temp_token}

    # Check if force 2FA is enabled and user hasn't set it up yet
    security_settings = await get_setting(db, "security")
    if security_settings and security_settings.get("force_2fa_on_signup", False):
        # User needs to set up 2FA before they can fully log in
        await clear_failed_attempts(db, email)
        access_token = await create_token_with_dynamic_timeout(str(user.id), db, user.token_version)
        await audit_log(
            db, user.id, "user.login", "user", str(user.id),
            {"email": user.email, "auth_method": "local", "requires_2fa_setup": True}, ip_address=ip_address
        )
        await db.commit()
        return {"access_token": access_token, "requires_2fa_setup": True}

    # Clear failed attempts on successful login
    await clear_failed_attempts(db, email)

    # Generate token with dynamic timeout
    access_token = await create_token_with_dynamic_timeout(str(user.id), db, user.token_version)
    await audit_log(
        db, user.id, "user.login", "user", str(user.id),
        {"email": user.email, "auth_method": "local"}, ip_address=ip_address
    )
    await db.commit()
    return TokenResponse(access_token=access_token)


@router.post("/logout")
async def logout():
    # For JWT, logout is handled client-side by deleting the token
    # Server-side token blacklisting can be added later
    return {"message": "Logged out successfully"}


@router.post("/change-password")
async def change_password(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Change password for local authentication users.

    This endpoint performs the following in a single atomic transaction:
    1. Verifies the current password
    2. Validates the new password meets complexity requirements
    3. Ensures new password is different from current password
    4. Updates the password hash
    5. Logs the change for audit purposes
    """
    # SSO users cannot change password
    if current_user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO users cannot change password in CHAD",
        )

    data = await request.json()
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not current_password or not new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password and new password are required",
        )

    # Verify current password
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # Validate password complexity (pass email for additional validation)
    is_valid, error_msg = validate_password_complexity(
        new_password,
        user_email=current_user.email,
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # Prevent reusing the current password
    if verify_password(new_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password",
        )

    # Audit log BEFORE commit (ensures atomic transaction)
    await audit_log(
        db,
        current_user.id,
        "user.password_change",
        "user",
        str(current_user.id),
        {},
        ip_address=get_client_ip(request),
    )

    # Update password and clear the must_change_password flag
    current_user.password_hash = get_password_hash(new_password)
    current_user.must_change_password = False
    current_user.token_version += 1  # Invalidate all existing tokens

    # Single atomic commit for both password update and audit log
    await db.commit()

    return {"message": "Password changed successfully"}


@router.get("/me")
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get current user info including role, 2FA status, and permissions."""
    from app.services.permissions import get_role_permissions

    # Get user's permissions
    permissions = await get_role_permissions(db, current_user.role)

    # Org-wide enforced MFA (I4): when on, a local user without TOTP must enrol.
    security_settings = await get_setting(db, "security")
    mfa_enforced = bool(security_settings and security_settings.get("enforce_mfa", False))
    mfa_required = (
        mfa_enforced
        and current_user.auth_method == AuthMethod.LOCAL
        and not current_user.totp_enabled
    )

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "auth_method": current_user.auth_method.value,
        "must_change_password": current_user.must_change_password,
        "totp_enabled": current_user.totp_enabled,
        "mfa_enforced": mfa_enforced,
        "mfa_required": mfa_required,
        "permissions": permissions,
        "notification_preferences": current_user.notification_preferences or {
            "browser_notifications": False,
            "severities": ["critical", "high"]
        },
        "chad_delegated_auth": app_settings.CHAD_DELEGATED_AUTH,
    }


@router.post("/revoke-all-sessions")
async def revoke_all_sessions(
    http_request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    """Invalidate every active session by bumping all users' token_version (I4).

    Forces every user (including this admin) to re-authenticate — the break-glass
    control for a suspected token compromise.
    """
    await db.execute(update(User).values(token_version=User.token_version + 1))
    await audit_log(
        db, admin.id, "auth.revoke_all_sessions", "user", None, {},
        ip_address=get_client_ip(http_request),
    )
    await db.commit()
    return {"message": "All sessions revoked. Every user must sign in again."}


@router.patch("/me/notifications")
async def update_notification_preferences(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Update current user's browser notification preferences."""
    data = await request.json()

    # Validate input
    valid_severities = {"critical", "high", "medium", "low", "informational"}
    browser_notifications = data.get("browser_notifications")
    severities = data.get("severities")

    if browser_notifications is not None and not isinstance(browser_notifications, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="browser_notifications must be a boolean",
        )

    if severities is not None:
        if not isinstance(severities, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="severities must be a list",
            )
        invalid = set(severities) - valid_severities
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severities: {invalid}. Must be one of: {valid_severities}",
            )

    # Get current preferences or defaults - create a NEW dict to ensure SQLAlchemy detects the change
    # (mutating JSONB in-place won't trigger SQLAlchemy's dirty tracking)
    existing = current_user.notification_preferences or {}
    new_prefs = {
        "browser_notifications": existing.get("browser_notifications", False),
        "severities": list(existing.get("severities", ["critical", "high"])),
    }

    # Update with new values
    if browser_notifications is not None:
        new_prefs["browser_notifications"] = browser_notifications
    if severities is not None:
        new_prefs["severities"] = severities

    current_user.notification_preferences = new_prefs
    await db.commit()

    return {"notification_preferences": new_prefs}


# ============================================================================
# SSO / OIDC Authentication
# ============================================================================


async def _get_sso_enforced(db: AsyncSession) -> bool:
    """SSO-only enforcement: env flag OR a GUI ``sso`` setting flag (GUI wins on True)."""
    if app_settings.sso_only:
        return True
    sso_config = await get_setting(db, "sso")
    return bool(sso_config and sso_config.get("sso_only"))


@router.get("/sso/status")
async def get_sso_status(
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get SSO configuration status for the login page.

    Returns the list of ENABLED providers (id, name) so the login page can
    render one button per provider, plus an ``sso_enforced`` flag. Legacy
    single-provider fields are kept for back-compat with older frontends.
    """
    result = await db.execute(
        select(SSOProvider).where(SSOProvider.enabled.is_(True)).order_by(SSOProvider.name)
    )
    providers = list(result.scalars().all())

    enabled = len(providers) > 0
    sso_enforced = await _get_sso_enforced(db)

    return {
        "enabled": enabled,
        "configured": enabled,
        # Back-compat single-provider fields (first enabled provider).
        "provider_name": providers[0].name if providers else "SSO",
        "sso_only": sso_enforced,
        "sso_enforced": sso_enforced,
        "providers": [
            {"id": str(p.id), "name": p.name} for p in providers
        ],
    }


@router.get("/sso/enforcement", response_model=SSOEnforcementResponse)
async def get_sso_enforcement(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Read the effective SSO-only enforcement flag (env OR GUI setting)."""
    return SSOEnforcementResponse(sso_enforced=await _get_sso_enforced(db))


@router.put("/sso/enforcement", response_model=SSOEnforcementResponse)
async def update_sso_enforcement(
    payload: SSOEnforcementUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Persist the GUI SSO-only enforcement flag.

    Writes the same ``sso`` setting ``sso_only`` flag that ``_get_sso_enforced``
    reads. Merges into the existing dict so other ``sso`` fields (e.g. a legacy
    encrypted client_secret) are preserved untouched. Note: when the env-level
    ``sso_only`` is set, enforcement stays on regardless of this flag.
    """
    existing = await get_setting(db, "sso") or {}
    new_value = dict(existing)
    new_value["sso_only"] = payload.sso_enforced
    await set_setting(db, "sso", new_value)

    await audit_log(
        db,
        current_user.id,
        "sso.enforcement_updated",
        "settings",
        "sso",
        {"sso_only": payload.sso_enforced},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return SSOEnforcementResponse(sso_enforced=await _get_sso_enforced(db))


def _register_oauth_client(sso_config: dict) -> None:
    """Back-compat shim retained for older callers/tests.

    The multi-provider flow builds Authlib clients per provider id via
    ``app.services.sso_providers``; this no longer mutates a global ``oidc``
    registry. Kept as a no-op-ish helper so any legacy import still resolves.
    """
    return None


def _coerce_user_role(value: str | UserRole | None) -> UserRole | None:
    """Coerce a stored role string to UserRole; None if unknown (never raises)."""
    if value is None:
        return None
    if isinstance(value, UserRole):
        return value
    try:
        return UserRole(str(value).lower())
    except ValueError:
        return None


def _provider_config_view(provider: SSOProvider) -> dict:
    """Adapt a provider row to the dict shape ``_get_role_from_claims`` expects."""
    return {
        "role_mapping_enabled": bool(provider.role_claim),
        "role_claim": provider.role_claim,
        "admin_values": provider.admin_values or "",
        "analyst_values": provider.analyst_values or "",
        "viewer_values": provider.viewer_values or "",
        "default_role": provider.default_role or "viewer",
    }


async def _load_enabled_provider(
    db: AsyncSession, provider_id: str | uuid.UUID | None
) -> SSOProvider | None:
    """Load the enabled provider for login/callback.

    With an explicit id, load that provider (must be enabled). Without one
    (legacy single-provider URL), fall back to the sole enabled provider.

    A non-UUID ``provider_id`` is treated as "no such provider" (returns None) —
    it must NEVER raise, so a malformed ``?provider=`` cannot 500 the login.
    """
    stmt = (
        select(SSOProvider)
        .options(selectinload(SSOProvider.group_mappings))
        .where(SSOProvider.enabled.is_(True))
    )
    if provider_id:
        try:
            pid = provider_id if isinstance(provider_id, uuid.UUID) else uuid.UUID(str(provider_id))
        except (ValueError, AttributeError, TypeError):
            return None
        stmt = stmt.where(SSOProvider.id == pid)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    result = await db.execute(stmt.order_by(SSOProvider.name))
    providers = list(result.scalars().all())
    # Only auto-pick when exactly one enabled provider exists.
    return providers[0] if len(providers) == 1 else None


@router.get("/sso/login")
async def sso_login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    provider_id: str | None = None,
):
    """Initiate SSO/OIDC login flow for a specific (or the sole) provider."""
    provider = await _load_enabled_provider(db, provider_id)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO provider not found or not enabled",
        )
    if not provider.issuer_url or not provider.client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO configuration is incomplete",
        )

    # SSRF guard runs inside build_provider_client; a bad issuer raises 400.
    try:
        client = build_provider_client(provider)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSO issuer is not allowed: {exc}",
        ) from exc

    # Build callback URL with a ``?provider=`` hint. Provider binding is enforced
    # cryptographically, not by this hint: Authlib stores the OAuth ``state`` (and
    # the auto-generated ``nonce``) in the session keyed by THIS provider's client
    # name (``oidc_{provider.id}``). In the callback, authorize_access_token looks
    # the state up under the resolved provider's client name — so a tampered
    # ``?provider=`` resolves a different client, finds no matching state, and
    # fails cleanly (state mismatch) rather than authenticating. The nonce is
    # validated against the id_token by authorize_access_token.
    app_url = await get_app_url(db)
    if app_url:
        base_url = app_url.rstrip("/")
        callback = f"{base_url}/api/auth/sso/callback"
    else:
        callback = str(request.url_for("sso_callback"))
    # Remember which provider this flow is for in the signed (non-tamperable)
    # session so the callback URL the IdP must allow-list stays clean — no
    # ``?provider=<uuid>`` to register. The callback still honours an explicit
    # ?provider= for backward compatibility with already-registered URIs.
    request.session["sso_provider_id"] = str(provider.id)

    return await client.authorize_redirect(request, callback)


async def _resolve_validated_userinfo(client, request, token) -> dict | None:
    """Return claims ONLY from a validated source, or None.

    Order:
    1. ``token["userinfo"]`` — populated by authorize_access_token after it
       validated the id_token signature + nonce (Authlib). Trusted.
    2. ``client.userinfo(token=token)`` — the IdP's UserInfo endpoint queried
       with the access token. Trusted.

    The raw ``token["id_token"]`` (an unverified JWT string) is NEVER read.
    """
    userinfo = token.get("userinfo")
    if userinfo and userinfo.get("email"):
        return dict(userinfo)
    try:
        fetched = await client.userinfo(token=token)
    except Exception as exc:  # pragma: no cover - network/IdP failure
        logger.warning("SSO userinfo fetch failed: %s", exc)
        return None
    if fetched and fetched.get("email"):
        return dict(fetched)
    return None


@router.get("/sso/callback")
async def sso_callback(request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    """Handle SSO/OIDC callback after successful authentication (provider-scoped)."""
    frontend_url = app_settings.FRONTEND_URL.rstrip("/")

    def _err(message: str) -> RedirectResponse:
        return RedirectResponse(
            url=f"{frontend_url}/login?{urlencode({'sso_error': message})}"
        )

    # Provider resolved from the signed session set at login (clean callback URL),
    # falling back to an explicit ?provider= for backward compat. A malformed/
    # unknown value resolves to None and yields a clean error redirect (never 500).
    provider_hint = request.query_params.get("provider") or request.session.get(
        "sso_provider_id"
    )
    provider = await _load_enabled_provider(db, provider_hint)
    if provider is None:
        return _err("SSO provider not found or not enabled")

    try:
        client = get_provider_client(provider)
    except ValueError as exc:
        return _err(f"SSO issuer is not allowed: {exc}")

    try:
        # authorize_access_token validates the id_token signature + nonce (bound
        # in the session state under THIS provider's client name) and populates
        # token["userinfo"]. A tampered ?provider= resolves a different client
        # and fails here with a state mismatch.
        token = await client.authorize_access_token(request)
    except Exception as e:
        return _err(f"Authentication failed: {str(e)}")

    # Claims must come from a VALIDATED source only (never the raw id_token).
    userinfo = await _resolve_validated_userinfo(client, request, token)
    if userinfo is None:
        return _err("SSO provider did not return a verified email")

    email = userinfo.get("email")
    if not email:
        return _err("Email not provided by SSO provider")
    # Normalize email (mirror the local-login path) to avoid case-variant dupes.
    email = str(email).lower()

    # Require the IdP to assert the email is verified before trusting it. Without
    # this, an unverified email claim could be used to take over an existing
    # account by email match (or silently convert a local account to SSO).
    # Secure by default; operators whose IdP omits the claim can opt out.
    if provider.require_email_verified:
        email_verified = userinfo.get("email_verified")
        if email_verified is not True and str(email_verified).lower() != "true":
            return _err("Email is not verified by the SSO provider")

    provider_view = _provider_config_view(provider)

    # Find or create user
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Determine role from claims if role mapping is enabled
    mapped_role = _get_role_from_claims(userinfo, provider_view)

    if not user:
        # Auto-create user from SSO. SSO-provisioned users NEVER auto-receive
        # admin from an empty user table — the local setup wizard is the only
        # path to the first admin. New users get the mapped/role-claim role, else
        # the provider default.
        if mapped_role:
            role = mapped_role
        else:
            role = _coerce_user_role(provider.default_role) or UserRole.VIEWER

        user = User(
            email=email,
            password_hash=None,  # SSO users have no local password
            role=role,
            auth_method=AuthMethod.SSO,
            provisioned_via=ProvisionedVia.SSO.value,
            is_active=True,
        )
        db.add(user)
        await db.flush()
    else:
        # SECURITY (C1): refuse silent LOCAL->SSO fusion. An OIDC sign-in whose
        # email matches an existing LOCAL (non-SSO) account is REFUSED — we never
        # null the password / convert the account. This closes the account-takeover
        # vector where an attacker who controls the email at the IdP could seize a
        # local admin account. Provenance (provisioned_via) is the source of truth;
        # auth_method is checked too for defence in depth.
        if (
            user.provisioned_via == ProvisionedVia.LOCAL.value
            or user.auth_method == AuthMethod.LOCAL
        ):
            await audit_log(
                db, user.id, "auth.sso_fusion_refused", "user", str(user.id),
                {"email": user.email, "provider": str(provider.id)},
                ip_address=get_client_ip(request),
            )
            await db.commit()
            return _err(
                "An account with this email already exists with password "
                "login. SSO sign-in for this account is not permitted. "
                "Contact an administrator."
            )

        # Role authority for an EXISTING user (resolve the double-writer):
        #   - If group sync is on AND a mapping matches -> reconcile owns role
        #     (handled below). We do NOT also apply the role-claim here.
        #   - Otherwise fall back to the role-claim sync (if enabled). We NEVER
        #     overwrite an existing user's role with the provider default.
        group_sync_active = bool(provider.group_sync_enabled and provider.groups_claim)
        if not group_sync_active and mapped_role and provider_view["role_mapping_enabled"]:
            if user.role != mapped_role:
                user.role = mapped_role

    # Group reconciliation (B): when the provider has group sync enabled, derive
    # team + role from the IdP groups claim. Single writer of group-sourced
    # membership AND role; never clobbers a manual assignment when no group
    # matches, and never demotes role on a non-match.
    if provider.group_sync_enabled and provider.groups_claim:
        raw_groups = userinfo.get(provider.groups_claim)
        if raw_groups is None:
            group_values: list[str] = []
        elif isinstance(raw_groups, list):
            group_values = [str(g) for g in raw_groups]
        else:
            group_values = [str(raw_groups)]
        recon = reconcile_user_team_memberships(user, group_values, provider)
        if recon.admin_granted_via_group:
            # Privileged promotion via IdP group must be visible in the audit log.
            await audit_log(
                db, user.id, "sso.group_admin_granted", "user", str(user.id),
                {"email": user.email, "provider": str(provider.id)},
                ip_address=get_client_ip(request),
            )

    await db.commit()
    await db.refresh(user)

    if not user.is_active:
        error_params = urlencode({"sso_error": "User account is inactive"})
        return RedirectResponse(url=f"{frontend_url}/login?{error_params}")

    # Generate short-lived exchange code (30 second validity)
    import secrets
    exchange_code = secrets.token_urlsafe(32)

    # Store in database with user_id and expiration
    from app.models.two_factor_token import TwoFactorToken
    await TwoFactorToken.create_token(
        db,
        user_id=exchange_code,  # Use code as the lookup key
        token_type="sso_exchange",
        token_data=str(user.id),  # Store user_id
        expires_minutes=0.5,  # 30 seconds
    )

    # Audit log the SSO login
    await audit_log(
        db, user.id, "user.login", "user", str(user.id),
        {"email": user.email, "auth_method": "sso"}, ip_address=get_client_ip(request)
    )
    await db.commit()

    # Redirect with exchange code instead of token
    return RedirectResponse(url=f"{frontend_url}/?sso_code={exchange_code}")


@router.post("/sso/exchange")
async def sso_exchange_token(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Exchange SSO code for JWT token."""
    data = await request.json()
    code = data.get("code")

    if not code:
        raise HTTPException(400, "Exchange code required")

    # Look up the exchange token
    from app.models.two_factor_token import TwoFactorToken
    exchange_token = await TwoFactorToken.get_valid_token(
        db,
        user_id=code,  # Use code as the lookup key
        token_type="sso_exchange",
    )

    if not exchange_token:
        raise HTTPException(401, "Invalid or expired exchange code")

    user_id = exchange_token.token_data

    # Get user and generate token
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(403, "User not found or inactive")

    # Delete the exchange token (single-use)
    await TwoFactorToken.delete_token(db, user_id=code, token_type="sso_exchange")

    # Generate JWT
    access_token = await create_token_with_dynamic_timeout(str(user.id), db, user.token_version)

    await audit_log(
        db, user.id, "user.login", "user", str(user.id),
        {"email": user.email, "auth_method": "sso"}, ip_address=get_client_ip(request)
    )
    await db.commit()

    return TokenResponse(access_token=access_token)


# ============================================================================
# Two-Factor Authentication (2FA)
# ============================================================================


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse, dependencies=[Depends(block_in_delegated_mode)])
async def setup_2fa(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Initiate 2FA setup. Returns QR code URI for authenticator app."""
    if current_user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO users cannot enable 2FA in CHAD. Use your identity provider's 2FA instead.",
        )
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled. Disable it first to set up again.",
        )

    secret = generate_totp_secret()
    qr_uri = generate_qr_uri(secret, current_user.email)
    # Store in database with 10-minute expiration
    from app.models.two_factor_token import TwoFactorToken
    await TwoFactorToken.create_token(
        db,
        user_id=str(current_user.id),
        token_type=TOKEN_TYPE_SETUP,
        token_data=secret,
        expires_minutes=10,
    )
    await db.commit()

    return TwoFactorSetupResponse(qr_uri=qr_uri, secret=secret)


@router.post("/2fa/verify", response_model=TwoFactorVerifyResponse, dependencies=[Depends(block_in_delegated_mode)])
async def verify_2fa_setup(
    request: TwoFactorVerifyRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Verify 2FA setup with code from authenticator app."""
    user_id = str(current_user.id)
    # Retrieve from database
    from app.models.two_factor_token import TwoFactorToken
    pending_token = await TwoFactorToken.get_valid_token(
        db,
        user_id=user_id,
        token_type=TOKEN_TYPE_SETUP,
    )
    if not pending_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup. Call /2fa/setup first.",
        )
    pending_secret = pending_token.token_data

    if not verify_totp_code(pending_secret, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please try again.",
        )

    backup_codes = generate_backup_codes(10)
    hashed_codes = [hash_backup_code(code) for code in backup_codes]

    current_user.totp_secret = pending_secret
    current_user.totp_enabled = True
    current_user.totp_backup_codes = hashed_codes

    # Delete the pending token
    await TwoFactorToken.delete_token(db, user_id=user_id, token_type=TOKEN_TYPE_SETUP)

    await db.commit()
    await audit_log(db, current_user.id, "user.2fa_enabled", "user", str(current_user.id), {})
    await db.commit()

    return TwoFactorVerifyResponse(message="2FA enabled successfully", backup_codes=backup_codes)


@router.post("/2fa/disable", dependencies=[Depends(block_in_delegated_mode)])
async def disable_2fa(
    request: TwoFactorDisableRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Disable 2FA. Requires valid TOTP or backup code."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled.")

    code_valid = verify_totp_code(current_user.totp_secret, request.code)

    if not code_valid and current_user.totp_backup_codes:
        for i, hashed in enumerate(current_user.totp_backup_codes):
            if verify_backup_code(request.code, hashed):
                code_valid = True
                current_user.totp_backup_codes = [
                    c for j, c in enumerate(current_user.totp_backup_codes) if j != i
                ]
                break

    if not code_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code.")

    current_user.totp_secret = None
    current_user.totp_enabled = False
    current_user.totp_backup_codes = None
    await db.commit()

    await audit_log(db, current_user.id, "user.2fa_disabled", "user", str(current_user.id), {})
    await db.commit()

    return {"message": "2FA disabled"}


@router.post("/login/2fa", dependencies=[Depends(block_in_delegated_mode)])
async def login_2fa(
    request: TwoFactorLoginRequest,
    http_request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Complete login with 2FA code."""
    ip_address = get_client_ip(http_request)
    # Retrieve from database
    from app.models.two_factor_token import TwoFactorToken
    pending_token = await TwoFactorToken.get_valid_token(
        db,
        user_id=request.token,
        token_type=TOKEN_TYPE_LOGIN,
    )
    if not pending_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired 2FA token. Please login again.",
        )
    user_id = pending_token.token_data

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found.")

    email = user.email.lower()

    # Throttle brute-force of the 2FA code. The password step clears failed
    # attempts before issuing the pending token, so without this the 6-digit
    # TOTP / backup codes can be guessed without limit. Reuse the same
    # account-lockout policy as the password login step.
    locked, lockout_minutes = await is_account_locked(db, email)
    if locked:
        await audit_log(
            db, user.id, "auth.lockout_login_attempt", "user", str(user.id),
            {"email": email}, ip_address=ip_address,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Account temporarily locked due to too many failed login attempts. "
                f"Try again in {lockout_minutes} minutes."
            ),
        )

    code_valid = verify_totp_code(user.totp_secret, request.code)

    if not code_valid and user.totp_backup_codes:
        for i, hashed in enumerate(user.totp_backup_codes):
            if verify_backup_code(request.code, hashed):
                code_valid = True
                user.totp_backup_codes = [c for j, c in enumerate(user.totp_backup_codes) if j != i]
                await db.commit()
                break

    if not code_valid:
        await record_failed_attempt(db, email, ip_address)
        await audit_log(
            db, user.id, "auth.login_failed", "user", str(user.id),
            {"email": email, "reason": "invalid_2fa_code"}, ip_address=ip_address,
        )
        # Notify + audit if this attempt tripped the lockout threshold
        locked_now, _ = await is_account_locked(db, email)
        if locked_now:
            await audit_log(
                db, user.id, "auth.lockout", "user", str(user.id),
                {"email": email}, ip_address=ip_address,
            )
            await send_system_notification(
                db, "user_locked", {"email": email, "ip_address": ip_address},
            )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code.")

    # Clear failed attempts on successful 2FA verification
    await clear_failed_attempts(db, email)

    # Delete the pending token after successful verification
    await TwoFactorToken.delete_token(db, user_id=request.token, token_type=TOKEN_TYPE_LOGIN)

    access_token = await create_token_with_dynamic_timeout(str(user.id), db, user.token_version)
    await audit_log(
        db, user.id, "user.login", "user", str(user.id), {"email": user.email, "auth_method": "local", "2fa": True}
    )
    await db.commit()

    return TokenResponse(access_token=access_token)
