"""Tests for MISP feedback service."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.ti.misp_feedback import EventCreationResult, MISPFeedbackService, SightingResult


@pytest.fixture
def mock_misp_client():
    """Create mock MISP client."""
    client = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_record_sighting_success(mock_misp_client):
    """Test recording a sighting in MISP."""
    mock_misp_client.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"Sighting": {"id": "12345"}},
    )

    service = MISPFeedbackService(mock_misp_client)
    result = await service.record_sighting(
        attribute_uuid="attr-uuid-123",
        source="CHAD",
        timestamp=datetime.now(UTC),
    )

    assert result.success is True
    assert result.sighting_id == "12345"
    mock_misp_client.post.assert_called_once()


@pytest.mark.asyncio
async def test_record_sighting_failure(mock_misp_client):
    """Test handling sighting recording failure."""
    mock_misp_client.post.side_effect = Exception("MISP API error")

    service = MISPFeedbackService(mock_misp_client)
    result = await service.record_sighting(
        attribute_uuid="attr-uuid-123",
        source="CHAD",
        timestamp=datetime.now(UTC),
    )

    assert result.success is False
    assert "MISP API error" in result.error


@pytest.mark.asyncio
async def test_record_false_positive(mock_misp_client):
    """Test recording a false positive sighting."""
    mock_misp_client.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"Sighting": {"id": "99999"}},
    )

    service = MISPFeedbackService(mock_misp_client)
    result = await service.record_sighting(
        attribute_uuid="attr-uuid-123",
        source="CHAD",
        timestamp=datetime.now(UTC),
        sighting_type=1,  # 1 = false positive
    )

    assert result.success is True
    # Verify the request included type=1
    call_args = mock_misp_client.post.call_args
    assert call_args.kwargs["json"]["type"] == 1


@pytest.mark.asyncio
async def test_create_event_success(mock_misp_client):
    """Test creating a MISP event from alert."""
    mock_misp_client.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"Event": {"id": "67890", "uuid": "event-uuid-new"}},
    )

    service = MISPFeedbackService(mock_misp_client)
    result = await service.create_event(
        info="CHAD Detection: Suspicious PowerShell Activity",
        threat_level=1,  # High
        distribution=0,  # Your org only
        tags=["source:chad", "tlp:amber"],
        attributes=[
            {"type": "ip-dst", "value": "192.168.1.100", "to_ids": True},
            {"type": "domain", "value": "evil.com", "to_ids": True},
        ],
    )

    assert result.success is True
    assert result.event_id == "67890"
    assert result.event_uuid == "event-uuid-new"


@pytest.mark.asyncio
async def test_create_event_failure(mock_misp_client):
    """Test handling event creation failure."""
    mock_misp_client.post.side_effect = Exception("Permission denied")

    service = MISPFeedbackService(mock_misp_client)
    result = await service.create_event(
        info="CHAD Detection",
        threat_level=1,
        attributes=[],
    )

    assert result.success is False
    assert "Permission denied" in result.error


def test_sighting_result_dataclass():
    """Test SightingResult dataclass."""
    result = SightingResult(success=True, sighting_id="123")
    assert result.success is True
    assert result.error is None


def test_event_creation_result_dataclass():
    """Test EventCreationResult dataclass."""
    result = EventCreationResult(
        success=True,
        event_id="456",
        event_uuid="uuid-456",
    )
    assert result.success is True
