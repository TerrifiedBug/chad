"""
API Key management endpoints.

Users can create and manage their own API keys for external API access.
"""

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID as PyUUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import get_password_hash, verify_password
from app.utils.request import get_client_ip
from app.db.session import get_db
from app.models.api_key import APIKey, generate_api_key
from app.models.user import User
from app.services.audit import audit_log
from app.schemas.api_key import (
    APIKeyCreate,
    APIKeyCreateResponse,
    APIKeyResponse,
    APIKeyUpdate,
)

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """List all API keys for the current user."""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == current_user.id)
        .order_by(APIKey.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=APIKeyCreateResponse)
async def create_api_key(
    data: APIKeyCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Create a new API key.

    The full key is only returned once in this response.
    Store it securely - it cannot be retrieved again.
    """
    # Generate the key
    raw_key = generate_api_key()
    key_prefix = raw_key[:12]  # "chad_" + first few chars
    key_hash = get_password_hash(raw_key)

    api_key = APIKey(
        name=data.name,
        description=data.description,
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=current_user.id,
        expires_at=data.expires_at,
    )

    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    await audit_log(db, current_user.id, "api_key.create", "api_key", str(api_key.id), {"name": api_key.name}, ip_address=get_client_ip(request))
    await db.commit()

    # Return the response with the raw key (only time it's shown)
    return APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        user_id=api_key.user_id,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        key=raw_key,  # Only returned on creation
    )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: PyUUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get a specific API key."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    return api_key


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: PyUUID,
    data: APIKeyUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Update an API key."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Update fields
    if data.name is not None:
        api_key.name = data.name
    if data.description is not None:
        api_key.description = data.description
    if data.is_active is not None:
        api_key.is_active = data.is_active

    await audit_log(db, current_user.id, "api_key.update", "api_key", str(api_key.id), {"name": api_key.name, "is_active": api_key.is_active}, ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(api_key)

    return api_key


@router.delete("/{key_id}")
async def delete_api_key(
    key_id: PyUUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Delete an API key."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    name = api_key.name  # Capture before delete
    await db.delete(api_key)
    await audit_log(db, current_user.id, "api_key.delete", "api_key", str(key_id), {"name": name}, ip_address=get_client_ip(request))
    await db.commit()

    return {"message": "API key deleted"}


async def validate_api_key(key: str, db: AsyncSession) -> User | None:
    """
    Validate an API key and return the associated user.

    Returns None if the key is invalid, expired, or inactive.
    """
    # Find by prefix first (more efficient than comparing all hashes)
    key_prefix = key[:12] if len(key) >= 12 else key

    result = await db.execute(
        select(APIKey)
        .where(APIKey.key_prefix == key_prefix, APIKey.is_active == True)
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        return None

    # Verify the full key hash
    if not verify_password(key, api_key.key_hash):
        return None

    # Check expiration
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        return None

    # Get the user
    user_result = await db.execute(
        select(User).where(User.id == api_key.user_id, User.is_active == True)
    )
    user = user_result.scalar_one_or_none()

    if not user:
        return None

    # Update last used timestamp
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    return user
