"""User management API (admin only)."""

import secrets
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import validate_password_complexity
from app.models.audit_log import AuditLog
from app.api.deps import get_db, require_admin, require_permission_dep
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class PasswordResetResponse(BaseModel):
    temporary_password: str
    message: str


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: str
    is_active: bool
    created_at: str
    auth_method: str  # "local" or "sso"
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    users: list[UserResponse]


@router.get("", response_model=UserListResponse)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """List all users (admin only)."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return UserListResponse(
        users=[
            UserResponse(
                id=u.id,
                email=u.email,
                role=u.role.value,
                is_active=u.is_active,
                created_at=u.created_at.isoformat(),
                auth_method=u.auth_method.value,
                totp_enabled=u.totp_enabled,
            )
            for u in users
        ]
    )


@router.get("/lock-status/{email}", response_model=dict)
async def get_user_lock_status(
    email: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Get lock status for a specific user."""
    from app.services.rate_limit import is_account_locked

    locked, remaining_minutes = await is_account_locked(db, email)

    return {
        "email": email,
        "locked": locked,
        "remaining_minutes": remaining_minutes
    }


@router.post("/{user_id}/unlock", response_model=dict)
async def unlock_user_account(
    user_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Unlock a user account by clearing failed login attempts."""
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Clear failed attempts
    from app.services.rate_limit import clear_failed_attempts

    cleared = await clear_failed_attempts(db, user.email)

    await audit_log(
        db,
        current_user.id,
        "user.unlock",
        "user",
        str(user_id),
        {"email": user.email},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return {
        "success": True,
        "email": user.email,
        "message": f"User account {user.email} unlocked successfully"
    }


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Create a new user (admin only)."""
    # Check if email already exists
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # Validate role
    try:
        role = UserRole(data.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {[r.value for r in UserRole]}",
        )

    user = User(
        email=data.email,
        password_hash=bcrypt.hash(data.password),
        role=role,
        must_change_password=True,  # New users must change password on first login
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await audit_log(db, current_user.id, "user.create", "user", str(user.id), {"email": user.email, "role": role.value}, ip_address=get_client_ip(request))
    await db.commit()

    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        auth_method="local",  # Created via API = always local
    )


@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Delete a user (admin only)."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent deleting the last admin user
    if user.role == UserRole.ADMIN:
        admin_count_result = await db.execute(
            select(User).where(User.role == UserRole.ADMIN, User.is_active == True)
        )
        admin_count = len(admin_count_result.scalars().all())
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last admin user",
            )

    email = user.email  # Capture before delete

    # Nullify user_id in audit_log to preserve audit trail while removing FK reference
    await db.execute(
        update(AuditLog).where(AuditLog.user_id == user_id).values(user_id=None)
    )

    await db.delete(user)
    await audit_log(db, current_user.id, "user.delete", "user", str(user_id), {"email": email}, ip_address=get_client_ip(request))
    await db.commit()
    return {"success": True}


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    data: UserUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Update a user's role or active status (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if user is SSO (no password_hash)
    is_sso_user = user.password_hash is None

    # SSO users cannot have their role changed if role mapping is enabled
    if data.role is not None and is_sso_user:
        # Check if SSO role mapping is enabled
        sso_result = await db.execute(select(Setting).where(Setting.key == "sso"))
        sso_setting = sso_result.scalar_one_or_none()
        sso_config = sso_setting.value if sso_setting else {}
        role_mapping_enabled = sso_config.get("role_mapping_enabled", False)

        if role_mapping_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change role for SSO users. Role is managed by the identity provider.",
            )

    # Validate role if provided
    if data.role is not None:
        try:
            role = UserRole(data.role)
            user.role = role
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {[r.value for r in UserRole]}",
            )

    # Update is_active if provided (allowed for both local and SSO users)
    if data.is_active is not None:
        user.is_active = data.is_active

    await audit_log(db, current_user.id, "user.update", "user", str(user_id), {"email": user.email, "role": data.role, "is_active": data.is_active}, ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(user)

    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        auth_method="local" if user.password_hash else "sso",
    )


@router.post("/{user_id}/reset-password", response_model=PasswordResetResponse)
async def reset_user_password(
    user_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_users"))],
):
    """Reset a user's password and generate a temporary password (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if user is SSO (no password_hash)
    if user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot reset password for SSO users. Authentication is managed by the identity provider.",
        )

    # Generate temporary password
    temporary_password = secrets.token_urlsafe(12)

    # Hash and update the password
    user.password_hash = bcrypt.hash(temporary_password)
    user.must_change_password = True

    await audit_log(db, current_user.id, "user.password_reset", "user", str(user_id), {"email": user.email}, ip_address=get_client_ip(request))
    await db.commit()

    return PasswordResetResponse(
        temporary_password=temporary_password,
        message="Password reset successful. User must change password on next login.",
    )
