"""Tests for the index patterns API endpoints."""

import pytest
from httpx import AsyncClient


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
