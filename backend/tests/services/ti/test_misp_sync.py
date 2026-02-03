"""Tests for MISP IOC sync service."""

from datetime import datetime, timedelta, UTC
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.ioc_types import IOCType, IOCRecord
from app.services.ti.misp_sync import MISPIOCFetcher


@pytest.fixture
def misp_fetcher():
    """Create a MISP IOC fetcher for testing."""
    return MISPIOCFetcher(
        api_key="test-api-key",
        instance_url="https://misp.example.com",
        verify_tls=True,
    )


@pytest.mark.asyncio
async def test_fetch_iocs_returns_records(misp_fetcher):
    """Test fetching IOCs returns IOCRecord list."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Attribute": [
            {
                "id": "1",
                "uuid": "attr-uuid-1",
                "event_id": "100",
                "type": "ip-dst",
                "value": "192.168.1.100",
                "Event": {
                    "uuid": "event-uuid-1",
                    "info": "APT29 Infrastructure",
                    "threat_level_id": "1",
                    "Tag": [{"name": "apt29"}, {"name": "tlp:amber"}],
                },
            },
            {
                "id": "2",
                "uuid": "attr-uuid-2",
                "event_id": "101",
                "type": "domain",
                "value": "evil.com",
                "Event": {
                    "uuid": "event-uuid-2",
                    "info": "Phishing Campaign",
                    "threat_level_id": "2",
                    "Tag": [{"name": "phishing"}],
                },
            },
        ]
    }

    with patch.object(misp_fetcher._client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        records = await misp_fetcher.fetch_iocs(
            threat_levels=["high", "medium"],
            ioc_types=[IOCType.IP_DST, IOCType.DOMAIN],
            max_age_days=30,
        )

        assert len(records) == 2
        assert isinstance(records[0], IOCRecord)
        assert records[0].ioc_type == IOCType.IP_DST
        assert records[0].value == "192.168.1.100"
        assert records[0].misp_event_id == "100"
        assert "apt29" in records[0].tags


@pytest.mark.asyncio
async def test_fetch_iocs_filters_by_to_ids(misp_fetcher):
    """Test that only to_ids=True attributes are fetched."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Attribute": []}

    with patch.object(misp_fetcher._client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        await misp_fetcher.fetch_iocs()

        # Verify the request includes to_ids filter
        call_args = mock_post.call_args
        request_body = call_args.kwargs.get("json", call_args.args[0] if call_args.args else {})
        assert request_body.get("to_ids") is True


@pytest.mark.asyncio
async def test_fetch_iocs_handles_empty_response(misp_fetcher):
    """Test handling of empty MISP response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Attribute": []}

    with patch.object(misp_fetcher._client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        records = await misp_fetcher.fetch_iocs()

        assert records == []


@pytest.mark.asyncio
async def test_fetch_iocs_handles_api_error(misp_fetcher):
    """Test handling of MISP API errors."""
    with patch.object(misp_fetcher._client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("Connection failed")

        with pytest.raises(Exception, match="Connection failed"):
            await misp_fetcher.fetch_iocs()


def test_map_threat_level_id_to_name():
    """Test mapping MISP threat level IDs to names."""
    fetcher = MISPIOCFetcher("key", "https://misp.example.com")
    assert fetcher._map_threat_level("1") == "high"
    assert fetcher._map_threat_level("2") == "medium"
    assert fetcher._map_threat_level("3") == "low"
    assert fetcher._map_threat_level("4") == "undefined"
    assert fetcher._map_threat_level("unknown") == "unknown"
