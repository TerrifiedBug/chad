from typing import Annotated

from fastapi import Depends, HTTPException, status, WebSocket
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.services.opensearch import create_client

security = HTTPBearer()


async def get_current_user_websocket(
    websocket: WebSocket,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User | None:
    """
    Authenticate WebSocket connection using token from query parameter.

    Returns the authenticated user or None if authentication fails.
    Used by WebSocket endpoints which need to handle auth differently.
    """
    from fastapi import Query

    # Get token from query parameter
    token = websocket.query_params.get("token")
    if not token:
        return None

    payload = decode_access_token(token)
    if payload is None:
        return None

    user_id = payload.get("sub")
    if user_id is None:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        return None

    return user


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


async def require_permission(
    permission: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Check if current user has a specific permission.

    Usage in endpoints:
        current_user: Annotated[User, Depends(require_permission("manage_rules"))]
    """
    from app.services.permissions import has_permission

    if not await has_permission(db, current_user, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission required: {permission}",
        )
    return current_user


def require_permission_dep(permission: str):
    """
    Create a dependency that requires a specific permission.

    Usage:
        @router.post(...)
        async def endpoint(
            current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
        ):
            ...
    """
    async def check_permission(
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        from app.services.permissions import has_permission

        if not await has_permission(db, current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return current_user

    return check_permission


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
    # Decrypt password if stored encrypted
    password = config.get("password")
    if password:
        try:
            password = decrypt(password)
        except Exception:
            # Password may be stored in plaintext (legacy) - use as-is
            pass

    return create_client(
        host=config["host"],
        port=config["port"],
        username=config.get("username"),
        password=password,
        use_ssl=config.get("use_ssl", True),
        verify_certs=config.get("verify_certs", True),  # Default to True for security
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
    # Decrypt password if stored encrypted
    password = config.get("password")
    if password:
        try:
            password = decrypt(password)
        except Exception:
            # Password may be stored in plaintext (legacy) - use as-is
            pass

    try:
        return create_client(
            host=config["host"],
            port=config["port"],
            username=config.get("username"),
            password=password,
            use_ssl=config.get("use_ssl", True),
            verify_certs=config.get("verify_certs", True),  # Default to True for security
        )
    except Exception:
        return None
