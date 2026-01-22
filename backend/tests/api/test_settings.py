"""Tests for settings API endpoints."""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


class TestAppUrl:
    """Tests for APP_URL settings."""

    async def test_app_url_crud(self, authenticated_client: AsyncClient):
        """Test APP_URL get and set."""
        # Initially empty
        response = await authenticated_client.get("/api/settings/app-url")
        assert response.status_code == 200
        assert response.json()["url"] == ""

        # Set valid URL
        response = await authenticated_client.put(
            "/api/settings/app-url",
            json={"url": "https://chad.example.com"}
        )
        assert response.status_code == 200

        # Verify saved
        response = await authenticated_client.get("/api/settings/app-url")
        assert response.json()["url"] == "https://chad.example.com"

        # Trailing slash stripped
        response = await authenticated_client.put(
            "/api/settings/app-url",
            json={"url": "https://chad.example.com/"}
        )
        assert response.status_code == 200
        response = await authenticated_client.get("/api/settings/app-url")
        assert response.json()["url"] == "https://chad.example.com"

    async def test_app_url_validation(self, authenticated_client: AsyncClient):
        """Test APP_URL validation."""
        response = await authenticated_client.put(
            "/api/settings/app-url",
            json={"url": "not-a-url"}
        )
        assert response.status_code == 400

    async def test_app_url_empty_allowed(self, authenticated_client: AsyncClient):
        """Test empty APP_URL is allowed (to clear setting)."""
        # Set a value first
        await authenticated_client.put(
            "/api/settings/app-url",
            json={"url": "https://chad.example.com"}
        )

        # Clear it
        response = await authenticated_client.put(
            "/api/settings/app-url",
            json={"url": ""}
        )
        assert response.status_code == 200

        # Verify cleared
        response = await authenticated_client.get("/api/settings/app-url")
        assert response.json()["url"] == ""

    async def test_app_url_requires_auth(self, client: AsyncClient):
        """Test APP_URL endpoints require authentication."""
        response = await client.get("/api/settings/app-url")
        assert response.status_code in (401, 403)  # FastAPI returns 403 for missing auth

        response = await client.put(
            "/api/settings/app-url",
            json={"url": "https://chad.example.com"}
        )
        assert response.status_code in (401, 403)
