from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, SetupRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


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

    # Store OpenSearch settings
    opensearch_setting = Setting(
        key="opensearch",
        value={
            "host": request.opensearch_host,
            "port": request.opensearch_port,
            "username": request.opensearch_username,
            "password": request.opensearch_password,
            "use_ssl": request.opensearch_use_ssl,
        },
    )
    db.add(opensearch_setting)

    await db.commit()
    await db.refresh(admin)

    # Generate token
    access_token = create_access_token(data={"sub": str(admin.id)})
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

    access_token = create_access_token(data={"sub": str(user.id)})
    return TokenResponse(access_token=access_token)


@router.post("/logout")
async def logout():
    # For JWT, logout is handled client-side by deleting the token
    # Server-side token blacklisting can be added later
    return {"message": "Logged out successfully"}
