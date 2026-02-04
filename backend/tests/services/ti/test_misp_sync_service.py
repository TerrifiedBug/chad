"""Tests for MISP sync service orchestrator."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from app.services.ti.ioc_types import IOCRecord, IOCType
from app.services.ti.misp_sync_service import MISPSyncResult, MISPSyncService


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


@pytest.mark.asyncio
async def test_sync_iocs_success(sample_records):
    """Test successful IOC sync."""
    mock_fetcher = AsyncMock()
    mock_fetcher.fetch_iocs.return_value = sample_records

    mock_cache = AsyncMock()
    mock_cache.bulk_store_iocs.return_value = 2

    mock_index = AsyncMock()
    mock_index.bulk_index_iocs.return_value = 2
    mock_index.delete_expired_iocs.return_value = 0

    service = MISPSyncService(
        fetcher=mock_fetcher,
        cache=mock_cache,
        index_service=mock_index,
    )

    result = await service.sync_iocs(
        threat_levels=["high", "medium"],
        ioc_types=[IOCType.IP_DST, IOCType.DOMAIN],
    )

    assert result.success is True
    assert result.iocs_fetched == 2
    assert result.iocs_cached == 2
    assert result.iocs_indexed == 2
    assert result.error is None


@pytest.mark.asyncio
async def test_sync_iocs_fetch_failure():
    """Test sync when MISP fetch fails."""
    mock_fetcher = AsyncMock()
    mock_fetcher.fetch_iocs.side_effect = Exception("MISP connection failed")

    mock_cache = AsyncMock()
    mock_index = AsyncMock()

    service = MISPSyncService(
        fetcher=mock_fetcher,
        cache=mock_cache,
        index_service=mock_index,
    )

    result = await service.sync_iocs()

    assert result.success is False
    assert "MISP connection failed" in result.error


@pytest.mark.asyncio
async def test_sync_iocs_partial_failure(sample_records):
    """Test sync when cache succeeds but index fails."""
    mock_fetcher = AsyncMock()
    mock_fetcher.fetch_iocs.return_value = sample_records

    mock_cache = AsyncMock()
    mock_cache.bulk_store_iocs.return_value = 2

    mock_index = AsyncMock()
    mock_index.bulk_index_iocs.side_effect = Exception("OpenSearch unavailable")
    mock_index.delete_expired_iocs.return_value = 0

    service = MISPSyncService(
        fetcher=mock_fetcher,
        cache=mock_cache,
        index_service=mock_index,
    )

    result = await service.sync_iocs()

    # Partial success - cache worked, index failed
    assert result.success is False
    assert result.iocs_cached == 2
    assert "OpenSearch unavailable" in result.error


@pytest.mark.asyncio
async def test_sync_iocs_cleans_expired():
    """Test that sync cleans up expired IOCs."""
    mock_fetcher = AsyncMock()
    mock_fetcher.fetch_iocs.return_value = []

    mock_cache = AsyncMock()
    mock_cache.bulk_store_iocs.return_value = 0

    mock_index = AsyncMock()
    mock_index.bulk_index_iocs.return_value = 0
    mock_index.delete_expired_iocs.return_value = 5

    service = MISPSyncService(
        fetcher=mock_fetcher,
        cache=mock_cache,
        index_service=mock_index,
    )

    result = await service.sync_iocs()

    assert result.expired_deleted == 5
    mock_index.delete_expired_iocs.assert_called_once()


def test_sync_result_dataclass():
    """Test MISPSyncResult dataclass."""
    result = MISPSyncResult(
        success=True,
        iocs_fetched=100,
        iocs_cached=100,
        iocs_indexed=100,
        expired_deleted=5,
        duration_ms=1234,
    )
    assert result.success is True
    assert result.error is None
