"""Database session configuration with connection pooling."""

import os
from collections.abc import AsyncGenerator
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

# Configurable pool settings via environment variables
# Allows tuning for different deployment sizes (single-worker dev vs multi-worker prod)
pool_size = int(os.getenv("DATABASE_POOL_SIZE", "20"))
max_overflow = int(os.getenv("DATABASE_MAX_OVERFLOW", "40"))

# When fronted by PgBouncer in transaction-pooling mode, SQLAlchemy must NOT keep
# its own connection pool (PgBouncer owns pooling) and must not reuse server-side
# prepared statements across pgbouncer-pooled backends. Per the SQLAlchemy asyncpg
# docs: NullPool + unique prepared-statement names + disabled statement cache.
# Many small uvicorn-worker pools (pool_size * workers * replicas) otherwise blow
# past Postgres max_connections; PgBouncer multiplexes them instead.
_pgbouncer = os.getenv("PGBOUNCER", "false").lower() in ("true", "1", "yes")

if _pgbouncer:
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={
            "statement_cache_size": 0,
            "prepared_statement_name_func": lambda: f"__asyncpg_{uuid4()}__",
        },
    )
else:
    # Direct-to-Postgres: SQLAlchemy owns the connection pool.
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
