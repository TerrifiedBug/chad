from datetime import timedelta
from typing import Annotated
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings as app_settings
from app.core.encryption import decrypt
from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.session import get_db
from app.models.user import User, UserRole, AuthMethod
from app.schemas.auth import LoginRequest, SetupRequest, TokenResponse
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
from app.services.settings import get_app_url, get_setting
from app.services.totp import (
    generate_backup_codes,
    generate_qr_uri,
    generate_totp_secret,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)
from app.utils.request import get_client_ip

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
    return {"setup_completed": user_count > 0}


@router.post("/setup", response_model=TokenResponse)
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


@router.post("/login")
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

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "auth_method": current_user.auth_method.value,
        "must_change_password": current_user.must_change_password,
        "totp_enabled": current_user.totp_enabled,
        "permissions": permissions,
    }


# ============================================================================
# SSO / OIDC Authentication
# ============================================================================


@router.get("/sso/status")
async def get_sso_status(
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Get SSO configuration status.

    Returns whether SSO is enabled, configured, and if SSO-only mode is active.
    """
    sso_config = await get_setting(db, "sso")
    if not sso_config:
        return {"enabled": False, "configured": False, "sso_only": app_settings.SSO_ONLY}

    return {
        "enabled": sso_config.get("enabled", False),
        "configured": bool(
            sso_config.get("issuer_url")
            and sso_config.get("client_id")
            and sso_config.get("client_secret")
        ),
        "provider_name": sso_config.get("provider_name", "SSO"),
        "sso_only": app_settings.SSO_ONLY
    }


def _register_oauth_client(sso_config: dict) -> None:
    """Register OAuth client with settings from database."""
    issuer_url = sso_config.get("issuer_url", "").rstrip("/")
    client_id = sso_config.get("client_id")
    client_secret_encrypted = sso_config.get("client_secret")

    # Decrypt client secret (it's stored encrypted in DB)
    client_secret = decrypt(client_secret_encrypted) if client_secret_encrypted else None

    # Re-register to ensure latest settings are used
    # authlib allows re-registration with same name
    oauth.register(
        name="oidc",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=f"{issuer_url}/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid email profile",
            "token_endpoint_auth_method": "client_secret_post",  # Some providers need this
        },
        overwrite=True,
    )


@router.get("/sso/login")
async def sso_login(request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    """Initiate SSO/OIDC login flow."""
    sso_config = await get_setting(db, "sso")
    if not sso_config or not sso_config.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO is not configured or enabled",
        )

    issuer_url = sso_config.get("issuer_url")
    client_id = sso_config.get("client_id")
    client_secret = sso_config.get("client_secret")

    if not all([issuer_url, client_id, client_secret]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO configuration is incomplete",
        )

    # Register OAuth client with current settings
    _register_oauth_client(sso_config)

    # Build callback URL
    # Use APP_URL from database settings if configured (for production behind reverse proxy)
    # Otherwise use request-derived URL
    app_url = await get_app_url(db)
    if app_url:
        base_url = app_url.rstrip("/")
        redirect_uri = f"{base_url}/api/auth/sso/callback"
    else:
        redirect_uri = str(request.url_for("sso_callback"))

    return await oauth.oidc.authorize_redirect(request, redirect_uri)


@router.get("/sso/callback")
async def sso_callback(request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    """Handle SSO/OIDC callback after successful authentication."""
    sso_config = await get_setting(db, "sso")
    if not sso_config or not sso_config.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO is not configured or enabled",
        )

    # Register OAuth client (needed for callback - separate request from login)
    _register_oauth_client(sso_config)

    # Get frontend URL for redirects
    frontend_url = app_settings.FRONTEND_URL.rstrip("/")

    try:
        # Get the token from the OAuth provider
        token = await oauth.oidc.authorize_access_token(request)
    except Exception as e:
        # Redirect to login with error
        error_params = urlencode({"sso_error": f"Authentication failed: {str(e)}"})
        return RedirectResponse(url=f"{frontend_url}/login?{error_params}")

    # Extract user info from token
    userinfo = token.get("userinfo")
    if not userinfo:
        # Try to get userinfo from id_token
        userinfo = token.get("id_token", {})

    email = userinfo.get("email")
    if not email:
        error_params = urlencode({"sso_error": "Email not provided by SSO provider"})
        return RedirectResponse(url=f"{frontend_url}/login?{error_params}")

    # Find or create user
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Determine role from claims if role mapping is enabled
    mapped_role = _get_role_from_claims(userinfo, sso_config)

    if not user:
        # Auto-create user from SSO
        # Determine role: first SSO user after setup becomes admin, others are analysts
        result = await db.execute(select(func.count()).select_from(User))
        user_count = result.scalar() or 0

        if user_count == 0:
            # First user is always admin
            role = UserRole.ADMIN
        elif mapped_role:
            # Use mapped role from IdP claims
            role = mapped_role
        else:
            # Fall back to default role
            default_role = sso_config.get("default_role", "analyst")
            role = UserRole(default_role)

        user = User(
            email=email,
            password_hash=None,  # SSO users have no local password
            role=role,
            auth_method=AuthMethod.SSO,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        # Existing user: if local user, convert to SSO-only
        if user.auth_method == AuthMethod.LOCAL:
            # Convert to SSO-only (remove local password)
            user.auth_method = AuthMethod.SSO
            user.password_hash = None  # Remove local password
            await audit_log(
                db,
                user.id,
                "auth.sso_conversion",
                "user",
                str(user.id),
                {"message": "Local user converted to SSO-only authentication"},
                ip_address=get_client_ip(request),
            )
            await db.commit()
            await db.refresh(user)
        elif user.auth_method == AuthMethod.SSO:
            # Already an SSO user, continue
            pass

        # Sync role from IdP if role mapping is enabled
        if mapped_role and sso_config.get("role_mapping_enabled"):
            if user.role != mapped_role:
                user.role = mapped_role
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


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    current_user: Annotated[User, Depends(get_current_user)],
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


@router.post("/2fa/verify", response_model=TwoFactorVerifyResponse)
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


@router.post("/2fa/disable")
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


@router.post("/login/2fa")
async def login_2fa(
    request: TwoFactorLoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Complete login with 2FA code."""
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

    code_valid = verify_totp_code(user.totp_secret, request.code)

    if not code_valid and user.totp_backup_codes:
        for i, hashed in enumerate(user.totp_backup_codes):
            if verify_backup_code(request.code, hashed):
                code_valid = True
                user.totp_backup_codes = [c for j, c in enumerate(user.totp_backup_codes) if j != i]
                await db.commit()
                break

    if not code_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code.")

    # Delete the pending token after successful verification
    await TwoFactorToken.delete_token(db, user_id=request.token, token_type=TOKEN_TYPE_LOGIN)

    access_token = await create_token_with_dynamic_timeout(str(user.id), db, user.token_version)
    await audit_log(
        db, user.id, "user.login", "user", str(user.id), {"email": user.email, "auth_method": "local", "2fa": True}
    )
    await db.commit()

    return TokenResponse(access_token=access_token)
