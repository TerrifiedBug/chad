"""Database session configuration with connection pooling."""

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

# Configurable pool settings via environment variables
# Allows tuning for different deployment sizes (single-worker dev vs multi-worker prod)
pool_size = int(os.getenv("DATABASE_POOL_SIZE", "20"))
max_overflow = int(os.getenv("DATABASE_MAX_OVERFLOW", "40"))

# Configure database engine with connection pooling
# Pool settings configured for production workloads
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    # Connection pool settings (configurable via env vars)
    pool_size=pool_size,  # Number of connections to maintain
    max_overflow=max_overflow,  # Additional connections allowed beyond pool_size
    pool_timeout=30,  # Seconds to wait before giving up on getting a connection
    pool_recycle=3600,  # Recycle connections after 1 hour (prevents stale connections)
    pool_pre_ping=True,  # Verify connections before using them
)

async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
