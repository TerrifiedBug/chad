"""Tests for OpenSearch indicator index service."""

from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock

import pytest

from app.services.ti.ioc_types import IOCType, IOCRecord
from app.services.ti.ioc_index import IOCIndexService, INDICATOR_INDEX_NAME


@pytest.fixture
def sample_records():
    """Create sample IOC records."""
    return [
        IOCRecord(
            ioc_type=IOCType.IP_DST,
            value="192.168.1.100",
            misp_event_id="4521",
            misp_event_uuid="abc-123",
            misp_attribute_uuid="def-456",
            threat_level="high",
            tags=["apt29"],
            expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
        IOCRecord(
            ioc_type=IOCType.DOMAIN,
            value="evil.com",
            misp_event_id="4522",
            misp_event_uuid="ghi-789",
            misp_attribute_uuid="jkl-012",
            threat_level="medium",
            tags=["phishing"],
            expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
    ]


def test_indicator_index_name():
    """Test indicator index name constant."""
    assert INDICATOR_INDEX_NAME == "chad-indicators"


@pytest.mark.asyncio
async def test_ensure_index_creates_if_not_exists():
    """Test index creation when it doesn't exist."""
    mock_client = MagicMock()
    mock_client.indices.exists.return_value = False
    mock_client.indices.create = MagicMock()

    service = IOCIndexService(mock_client)
    await service.ensure_index()

    mock_client.indices.exists.assert_called_with(INDICATOR_INDEX_NAME)
    mock_client.indices.create.assert_called_once()


@pytest.mark.asyncio
async def test_ensure_index_skips_if_exists():
    """Test index creation skipped when index exists."""
    mock_client = MagicMock()
    mock_client.indices.exists.return_value = True

    service = IOCIndexService(mock_client)
    await service.ensure_index()

    mock_client.indices.exists.assert_called_with(INDICATOR_INDEX_NAME)
    mock_client.indices.create.assert_not_called()


@pytest.mark.asyncio
async def test_bulk_index_iocs(sample_records):
    """Test bulk indexing IOCs to OpenSearch."""
    mock_client = MagicMock()
    mock_client.bulk.return_value = {"errors": False, "items": [{}, {}]}

    service = IOCIndexService(mock_client)
    count = await service.bulk_index_iocs(sample_records)

    assert count == 2
    mock_client.bulk.assert_called_once()


@pytest.mark.asyncio
async def test_bulk_index_iocs_empty_list():
    """Test bulk indexing with empty list."""
    mock_client = MagicMock()

    service = IOCIndexService(mock_client)
    count = await service.bulk_index_iocs([])

    assert count == 0
    mock_client.bulk.assert_not_called()


@pytest.mark.asyncio
async def test_delete_expired_iocs():
    """Test deleting expired IOCs."""
    mock_client = MagicMock()
    mock_client.delete_by_query.return_value = {"deleted": 5}

    service = IOCIndexService(mock_client)
    count = await service.delete_expired_iocs()

    assert count == 5
    mock_client.delete_by_query.assert_called_once()


@pytest.mark.asyncio
async def test_get_ioc_count():
    """Test getting IOC count from index."""
    mock_client = MagicMock()
    mock_client.count.return_value = {"count": 1247}

    service = IOCIndexService(mock_client)
    count = await service.get_ioc_count()

    assert count == 1247
    mock_client.count.assert_called_with(index=INDICATOR_INDEX_NAME)


@pytest.mark.asyncio
async def test_clear_all_iocs():
    """Test clearing all IOCs from index."""
    mock_client = MagicMock()
    mock_client.delete_by_query.return_value = {"deleted": 100}

    service = IOCIndexService(mock_client)
    count = await service.clear_all_iocs()

    assert count == 100
