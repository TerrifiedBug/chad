"""Integration tests for authentication flow using testcontainers."""

import pytest

# Skip entire module if testcontainers is not installed
pytest.importorskip("testcontainers", reason="testcontainers not installed")

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from testcontainers.postgres import PostgresContainer

from app.db.base import Base
from app.main import app
from app.api.deps import get_db
from app.models.user import User, UserRole


@pytest.fixture(scope="module")
def postgres_container():
    """Spin up a PostgreSQL container for testing."""
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres


@pytest.fixture(scope="module")
async def db_engine(postgres_container):
    """Create a database engine for testing."""
    connection_url = postgres_container.get_connection_url()
    engine = create_async_engine(
        connection_url.replace("postgresql://", "postgresql+asyncpg://"),
        poolclass=NullPool,
    )

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="module")
async def db_session(db_engine):
    """Create a database session for testing."""
    async_session_maker = async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session_maker() as session:
        yield session


@pytest.fixture
async def client(db_session):
    """Create an async HTTP client for testing."""
    # We need to override the get_db dependency
    from unittest.mock import AsyncMock, patch

    async def override_get_db():
        return db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_setup_flow(client):
    """Test the initial setup flow creates admin user."""
    response = await client.get("/api/auth/setup-status")
    assert response.status_code == 200
    assert response.json()["setup_completed"] is False

    # Complete setup
    response = await client.post(
        "/api/auth/setup",
        json={
            "admin_email": "admin@test.com",
            "admin_password": "Test@12345",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Verify setup is complete
    response = await client.get("/api/auth/setup-status")
    assert response.status_code == 200
    assert response.json()["setup_completed"] is True


@pytest.mark.asyncio
async def test_login_flow(client, db_session):
    """Test local authentication login flow."""
    # Create a test user
    from app.core.security import get_password_hash

    user = User(
        email="test@example.com",
        password_hash=get_password_hash("Test@12345"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    # Test login
    response = await client.post(
        "/api/auth/login",
        json={
            "email": "test@example.com",
            "password": "Test@12345",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Test accessing protected endpoint
    token = response.json()["access_token"]
    response = await client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_invalid_credentials(client, db_session):
    """Test login with invalid credentials."""
    # Create a test user
    from app.core.security import get_password_hash

    user = User(
        email="test@example.com",
        password_hash=get_password_hash("Test@12345"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    # Test login with wrong password
    response = await client.post(
        "/api/auth/login",
        json={
            "email": "test@example.com",
            "password": "WrongPassword",
        },
    )
    assert response.status_code == 401
