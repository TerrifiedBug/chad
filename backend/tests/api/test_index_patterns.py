"""Tests for the index patterns API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.user import User, UserRole


@pytest_asyncio.fixture(scope="function")
async def non_admin_user(test_session: AsyncSession) -> User:
    """Create a non-admin test user."""
    user = User(
        id=uuid.uuid4(),
        email="viewer@example.com",
        password_hash=get_password_hash("viewerpassword"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def non_admin_token(non_admin_user: User) -> str:
    """Create a JWT token for the non-admin user."""
    return create_access_token(data={"sub": str(non_admin_user.id)})


@pytest_asyncio.fixture(scope="function")
async def non_admin_client(test_session: AsyncSession, non_admin_token: str):
    """Create an authenticated test client for a non-admin user."""
    async def override():
        yield test_session

    app.dependency_overrides[get_db] = override

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {non_admin_token}"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


class TestIndexPatternCRUD:
    """Tests for index pattern CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_index_pattern(self, authenticated_client: AsyncClient):
        """Create a new index pattern."""
        response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Windows Sysmon Logs",
                "pattern": "logs-windows-sysmon-*",
                "percolator_index": "percolator-sysmon",
                "description": "Windows Sysmon event logs",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Windows Sysmon Logs"
        assert data["pattern"] == "logs-windows-sysmon-*"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_list_index_patterns(self, authenticated_client: AsyncClient):
        """List all index patterns."""
        response = await authenticated_client.get("/api/index-patterns")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_index_pattern_not_found(self, authenticated_client: AsyncClient):
        """Get non-existent index pattern returns 404."""
        response = await authenticated_client.get(
            "/api/index-patterns/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404

    @pytest.mark.skip(reason="Update endpoint requires OpenSearch - use integration tests")
    @pytest.mark.asyncio
    async def test_update_index_pattern(self, authenticated_client: AsyncClient):
        """Update an existing index pattern."""
        # First create one
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Pattern",
                "pattern": "test-*",
                "percolator_index": "percolator-test",
                "description": "Initial description",
            },
        )
        assert create_response.status_code == 201
        pattern_id = create_response.json()["id"]

        # Then update it using PATCH
        update_response = await authenticated_client.patch(
            f"/api/index-patterns/{pattern_id}",
            json={
                "name": "Updated Pattern",
                "pattern": "updated-*",
                "description": "Updated description",
            },
        )
        assert update_response.status_code == 200
        data = update_response.json()
        assert data["name"] == "Updated Pattern"
        assert data["pattern"] == "updated-*"

    @pytest.mark.asyncio
    async def test_delete_index_pattern(self, authenticated_client: AsyncClient):
        """Delete an index pattern."""
        # First create one
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "To Delete",
                "pattern": "delete-me-*",
                "percolator_index": "percolator-delete",
            },
        )
        assert create_response.status_code == 201
        pattern_id = create_response.json()["id"]

        # Then delete it
        delete_response = await authenticated_client.delete(
            f"/api/index-patterns/{pattern_id}"
        )
        assert delete_response.status_code == 204

        # Verify it's gone
        get_response = await authenticated_client.get(
            f"/api/index-patterns/{pattern_id}"
        )
        assert get_response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_requires_auth(self, client: AsyncClient):
        """Create index pattern requires authentication."""
        response = await client.post(
            "/api/index-patterns",
            json={
                "name": "Test",
                "pattern": "test-*",
                "percolator_index": "percolator-test",
            },
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403


class TestIndexPatternAuthToken:
    """Tests for index pattern auth token functionality."""

    @pytest.mark.asyncio
    async def test_create_generates_auth_token(self, authenticated_client: AsyncClient):
        """Creating an index pattern auto-generates an auth token."""
        response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Token Test Pattern",
                "pattern": "token-test-*",
                "percolator_index": "chad-percolator-token-test",
            },
        )
        assert response.status_code == 201
        data = response.json()

        # Auth token should be present and valid format
        assert "auth_token" in data
        assert data["auth_token"] is not None
        assert len(data["auth_token"]) >= 32  # secrets.token_urlsafe(32) generates ~43 chars

    @pytest.mark.asyncio
    async def test_list_includes_auth_token(self, authenticated_client: AsyncClient):
        """List endpoint includes auth tokens for each pattern."""
        # Create a pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "List Token Test",
                "pattern": "list-token-*",
                "percolator_index": "chad-percolator-list-token",
            },
        )
        assert create_response.status_code == 201

        # List and verify token is present
        list_response = await authenticated_client.get("/api/index-patterns")
        assert list_response.status_code == 200
        patterns = list_response.json()

        assert len(patterns) > 0
        for pattern in patterns:
            assert "auth_token" in pattern
            assert pattern["auth_token"] is not None

    @pytest.mark.asyncio
    async def test_regenerate_token(self, authenticated_client: AsyncClient):
        """Admin can regenerate the auth token for an index pattern."""
        # Create a pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Regenerate Token Test",
                "pattern": "regen-token-*",
                "percolator_index": "chad-percolator-regen-token",
            },
        )
        assert create_response.status_code == 201
        pattern_id = create_response.json()["id"]
        original_token = create_response.json()["auth_token"]

        # Regenerate the token
        regen_response = await authenticated_client.post(
            f"/api/index-patterns/{pattern_id}/regenerate-token",
            json={}
        )
        assert regen_response.status_code == 200
        new_token = regen_response.json()["auth_token"]

        # Token should be different
        assert new_token != original_token
        assert len(new_token) >= 32

    @pytest.mark.asyncio
    async def test_regenerate_token_not_found(self, authenticated_client: AsyncClient):
        """Regenerate token for non-existent pattern returns 404."""
        response = await authenticated_client.post(
            "/api/index-patterns/00000000-0000-0000-0000-000000000000/regenerate-token",
            json={}
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_regenerate_token_requires_auth(self, client: AsyncClient):
        """Regenerate token requires authentication."""
        response = await client.post(
            "/api/index-patterns/00000000-0000-0000-0000-000000000000/regenerate-token",
            json={}
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_regenerate_token_requires_admin(
        self, authenticated_client: AsyncClient, non_admin_client: AsyncClient
    ):
        """Non-admin users cannot regenerate tokens."""
        # Create a pattern with admin
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Admin Only Test",
                "pattern": "admin-only-*",
                "percolator_index": "chad-percolator-admin-only",
            },
        )
        assert create_response.status_code == 201
        pattern_id = create_response.json()["id"]

        # Try to regenerate with non-admin user
        response = await non_admin_client.post(
            f"/api/index-patterns/{pattern_id}/regenerate-token",
            json={}
        )
        assert response.status_code == 403


class TestIndexPatternValidation:
    """Tests for POST /index-patterns/validate endpoint."""

    @pytest.mark.asyncio
    async def test_validate_requires_auth(self, client: AsyncClient):
        """Validate endpoint requires authentication."""
        response = await client.post(
            "/api/index-patterns/validate",
            json={"pattern": "logs-*"},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403
