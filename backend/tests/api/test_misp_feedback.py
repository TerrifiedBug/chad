"""Tests for MISP feedback API endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_record_sighting(authenticated_client: AsyncClient):
    """Test recording a sighting via API."""
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.sighting_id = "12345"
    mock_result.error = None

    with patch(
        "app.api.misp_feedback.create_feedback_service", new_callable=AsyncMock
    ) as mock_create:
        mock_service = AsyncMock()
        mock_service.record_sighting.return_value = mock_result
        mock_create.return_value = mock_service

        response = await authenticated_client.post(
            "/api/misp/feedback/sighting",
            json={
                "attribute_uuid": "attr-uuid-123",
                "source": "CHAD",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["sighting_id"] == "12345"


@pytest.mark.asyncio
async def test_record_false_positive(authenticated_client: AsyncClient):
    """Test recording a false positive via API."""
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.sighting_id = "99999"
    mock_result.error = None

    with patch(
        "app.api.misp_feedback.create_feedback_service", new_callable=AsyncMock
    ) as mock_create:
        mock_service = AsyncMock()
        mock_service.record_sighting.return_value = mock_result
        mock_create.return_value = mock_service

        response = await authenticated_client.post(
            "/api/misp/feedback/sighting",
            json={
                "attribute_uuid": "attr-uuid-123",
                "source": "CHAD",
                "is_false_positive": True,
            },
        )

        assert response.status_code == 200
        # Verify false positive type was passed
        mock_service.record_sighting.assert_called_once()
        call_kwargs = mock_service.record_sighting.call_args.kwargs
        assert call_kwargs.get("sighting_type") == 1


@pytest.mark.asyncio
async def test_create_event_from_alert(authenticated_client: AsyncClient):
    """Test creating MISP event from alert."""
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.event_id = "67890"
    mock_result.event_uuid = "event-uuid-new"
    mock_result.error = None

    with patch(
        "app.api.misp_feedback.create_feedback_service", new_callable=AsyncMock
    ) as mock_create:
        mock_service = AsyncMock()
        mock_service.create_event.return_value = mock_result
        mock_create.return_value = mock_service

        response = await authenticated_client.post(
            "/api/misp/feedback/event",
            json={
                "alert_id": "alert-uuid-123",
                "info": "CHAD Detection: Suspicious Activity",
                "threat_level": 1,
                "attributes": [
                    {"type": "ip-dst", "value": "192.168.1.100"},
                ],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["event_id"] == "67890"


@pytest.mark.asyncio
async def test_feedback_requires_auth(client: AsyncClient):
    """Test that feedback endpoints require authentication."""
    response = await client.post(
        "/api/misp/feedback/sighting",
        json={"attribute_uuid": "test"},
    )
    # Either 401 (unauthorized) or 403 (CSRF check) when not authenticated
    assert response.status_code in (401, 403)
