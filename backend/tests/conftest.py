"""Pytest fixtures for backend tests."""

import uuid
from collections.abc import AsyncGenerator
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.security import create_access_token, get_password_hash
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.user import User, UserRole


# Use a SEPARATE test database to avoid destroying development data
TEST_DB_NAME = os.environ.get('TEST_POSTGRES_DB', 'chad_test')
POSTGRES_URL = (
    f"postgresql+asyncpg://{os.environ.get('POSTGRES_USER', 'chad')}:"
    f"{os.environ.get('POSTGRES_PASSWORD', 'devpassword')}@"
    f"{os.environ.get('POSTGRES_HOST', 'postgres')}:"
    f"{os.environ.get('POSTGRES_PORT', '5432')}"
)
TEST_DATABASE_URL = f"{POSTGRES_URL}/{TEST_DB_NAME}"


@pytest.fixture(scope="session", autouse=True)
def create_test_database():
    """Create the test database if it doesn't exist."""
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    async def _create_db():
        # Connect to default 'postgres' database to create test db
        engine = create_async_engine(
            f"{POSTGRES_URL}/postgres",
            isolation_level="AUTOCOMMIT",
            poolclass=NullPool,
        )
        async with engine.connect() as conn:
            # Check if database exists
            result = await conn.execute(
                text(f"SELECT 1 FROM pg_database WHERE datname = '{TEST_DB_NAME}'")
            )
            exists = result.scalar() is not None

            if not exists:
                await conn.execute(text(f'CREATE DATABASE "{TEST_DB_NAME}"'))

        await engine.dispose()

    asyncio.get_event_loop().run_until_complete(_create_db())


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create a test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Drop all tables and enum types to ensure clean state
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        # Drop custom enum types that may persist after drop_all
        await conn.execute(text("DROP TYPE IF EXISTS rulestatus CASCADE"))
        await conn.execute(text("DROP TYPE IF EXISTS rulesource CASCADE"))
        await conn.execute(text("DROP TYPE IF EXISTS mappingorigin CASCADE"))
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Clean up tables after each test function
    async with engine.begin() as conn:
        # Delete in correct order to respect foreign keys
        await conn.run_sync(Base.metadata.drop_all)
        # Drop enum types for next test
        await conn.execute(text("DROP TYPE IF EXISTS rulestatus CASCADE"))
        await conn.execute(text("DROP TYPE IF EXISTS rulesource CASCADE"))
        await conn.execute(text("DROP TYPE IF EXISTS mappingorigin CASCADE"))
        await conn.run_sync(Base.metadata.create_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def test_user(test_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        password_hash=get_password_hash("testpassword"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def test_token(test_user: User) -> str:
    """Create a test JWT token."""
    return create_access_token(data={"sub": str(test_user.id)})


@pytest_asyncio.fixture(scope="function")
async def client(test_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create an unauthenticated test client."""
    # Override get_db with our test session
    async def override():
        yield test_session

    app.dependency_overrides[get_db] = override

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def authenticated_client(
    test_session: AsyncSession, test_token: str
) -> AsyncGenerator[AsyncClient, None]:
    """Create an authenticated test client."""

    async def override():
        yield test_session

    app.dependency_overrides[get_db] = override

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {test_token}"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
