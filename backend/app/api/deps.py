from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.services.opensearch import create_client

security = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    token = credentials.credentials
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    return user


async def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    from app.models.user import UserRole

    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def get_opensearch_client(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> OpenSearch:
    """Get OpenSearch client from stored configuration."""
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = result.scalar_one_or_none()

    if setting is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OpenSearch not configured. Please configure OpenSearch in settings.",
        )

    config = setting.value
    return create_client(
        host=config["host"],
        port=config["port"],
        username=config.get("username"),
        password=config.get("password"),
        use_ssl=config.get("use_ssl", True),
    )


async def get_opensearch_client_optional(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> OpenSearch | None:
    """
    Get OpenSearch client if configured, otherwise return None.

    Use this for endpoints where OpenSearch is optional (e.g., rule updates
    that may need to sync to percolator but shouldn't fail if OS isn't configured).
    """
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = result.scalar_one_or_none()

    if setting is None:
        return None

    config = setting.value
    try:
        return create_client(
            host=config["host"],
            port=config["port"],
            username=config.get("username"),
            password=config.get("password"),
            use_ssl=config.get("use_ssl", True),
        )
    except Exception:
        return None
