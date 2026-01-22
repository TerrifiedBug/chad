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
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, SetupRequest, TokenResponse
from app.services.audit import audit_log
from app.services.settings import get_app_url, get_setting

router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth client instance
oauth = OAuth()

# Default session timeout in minutes (8 hours)
DEFAULT_SESSION_TIMEOUT_MINUTES = 480


def validate_password_complexity(password: str) -> tuple[bool, str]:
    """
    Validate password meets complexity requirements.

    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character

    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:',.<>?/`~)"

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


async def create_token_with_dynamic_timeout(user_id: str, db: AsyncSession) -> str:
    """Create JWT with configurable expiration from settings."""
    session_config = await get_setting(db, "session")
    timeout_minutes = (
        session_config.get("timeout_minutes", DEFAULT_SESSION_TIMEOUT_MINUTES)
        if session_config
        else DEFAULT_SESSION_TIMEOUT_MINUTES
    )
    expires_delta = timedelta(minutes=timeout_minutes)
    return create_access_token(data={"sub": user_id}, expires_delta=expires_delta)


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
    access_token = await create_token_with_dynamic_timeout(str(admin.id), db)
    return TokenResponse(access_token=access_token)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if user is None or user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    # Generate token with dynamic timeout
    access_token = await create_token_with_dynamic_timeout(str(user.id), db)
    await audit_log(db, user.id, "user.login", "user", str(user.id), {"email": user.email, "auth_method": "local"})
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
    """Change password for local authentication users."""
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

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # Update password and clear the must_change_password flag
    current_user.password_hash = get_password_hash(new_password)
    current_user.must_change_password = False
    await db.commit()
    await audit_log(db, current_user.id, "user.password_change", "user", str(current_user.id), {})
    await db.commit()

    return {"message": "Password changed successfully"}


@router.get("/me")
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get current user info including role."""
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "auth_method": "local" if current_user.password_hash else "sso",
        "must_change_password": current_user.must_change_password,
    }


# ============================================================================
# SSO / OIDC Authentication
# ============================================================================


@router.get("/sso/status")
async def get_sso_status(db: Annotated[AsyncSession, Depends(get_db)]):
    """Check if SSO is configured and enabled."""
    sso_config = await get_setting(db, "sso")
    if not sso_config:
        return {"enabled": False, "configured": False}

    return {
        "enabled": sso_config.get("enabled", False),
        "configured": bool(
            sso_config.get("issuer_url")
            and sso_config.get("client_id")
            and sso_config.get("client_secret")
        ),
        "provider_name": sso_config.get("provider_name", "SSO"),
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
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    elif mapped_role and sso_config.get("role_mapping_enabled"):
        # Existing user: sync role from IdP if role mapping is enabled
        if user.role != mapped_role:
            user.role = mapped_role
            await db.commit()
            await db.refresh(user)

    if not user.is_active:
        error_params = urlencode({"sso_error": "User account is inactive"})
        return RedirectResponse(url=f"{frontend_url}/login?{error_params}")

    # Create JWT token
    access_token = await create_token_with_dynamic_timeout(str(user.id), db)
    await audit_log(db, user.id, "user.login", "user", str(user.id), {"email": user.email, "auth_method": "sso"})
    await db.commit()

    # Redirect to frontend with token
    # The frontend will extract this and store it
    return RedirectResponse(url=f"{frontend_url}/?sso_token={access_token}")
