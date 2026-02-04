"""Tests for MISP sync API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_sync_status(authenticated_client: AsyncClient):
    """Test getting MISP sync status."""
    with patch(
        "app.api.misp_sync.get_sync_status_from_db", new_callable=AsyncMock
    ) as mock_status:
        mock_status.return_value = {
            "last_sync_at": "2026-02-03T19:45:00Z",
            "iocs_synced": 1247,
            "sync_duration_ms": 5432,
            "redis_ioc_count": 1247,
            "opensearch_ioc_count": 1247,
        }

        response = await authenticated_client.get("/api/misp/sync/status")

        assert response.status_code == 200
        data = response.json()
        assert data["iocs_synced"] == 1247


@pytest.mark.asyncio
async def test_trigger_sync(authenticated_client: AsyncClient):
    """Test triggering manual MISP sync."""
    with patch(
        "app.api.misp_sync.trigger_misp_sync", new_callable=AsyncMock
    ) as mock_trigger:
        mock_trigger.return_value = {
            "success": True,
            "iocs_fetched": 100,
            "iocs_cached": 100,
            "iocs_indexed": 100,
        }

        response = await authenticated_client.post("/api/misp/sync/trigger", json={})

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


@pytest.mark.asyncio
async def test_get_sync_config(authenticated_client: AsyncClient):
    """Test getting MISP sync configuration."""
    response = await authenticated_client.get("/api/misp/sync/config")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_update_sync_config(authenticated_client: AsyncClient):
    """Test updating MISP sync configuration."""
    config = {
        "enabled": True,
        "interval_minutes": 15,
        "threat_levels": ["high", "medium"],
        "max_age_days": 30,
    }

    response = await authenticated_client.put(
        "/api/misp/sync/config",
        json=config,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_trigger_sync_requires_auth(client: AsyncClient):
    """Test that trigger sync requires authentication."""
    response = await client.post(
        "/api/misp/sync/trigger",
        json={},
    )
    # Returns 403 (CSRF check) or 401 (auth) when not authenticated
    assert response.status_code in (401, 403)
