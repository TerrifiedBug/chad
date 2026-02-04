"""Tests for Redis IOC cache service."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.ioc_cache import IOCCache
from app.services.ti.ioc_types import IOCRecord, IOCType


@pytest.fixture
def sample_ioc_record():
    """Create a sample IOC record."""
    return IOCRecord(
        ioc_type=IOCType.IP_DST,
        value="192.168.1.100",
        misp_event_id="4521",
        misp_event_uuid="abc-123",
        misp_attribute_uuid="def-456",
        threat_level="high",
        tags=["apt29", "tlp:amber"],
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )


@pytest.fixture
def mock_redis():
    """Create a properly configured mock Redis client."""
    mock = AsyncMock()
    return mock


@pytest.mark.asyncio
async def test_store_ioc_sets_redis_key(sample_ioc_record, mock_redis):
    """Test storing an IOC sets the correct Redis key."""
    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        await cache.store_ioc(sample_ioc_record)

        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == "chad:ioc:ip-dst:192.168.1.100"


@pytest.mark.asyncio
async def test_store_ioc_sets_ttl(sample_ioc_record, mock_redis):
    """Test storing an IOC sets TTL based on expires_at."""
    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        await cache.store_ioc(sample_ioc_record)

        call_args = mock_redis.set.call_args
        # Should have ex (expiry) argument
        assert "ex" in call_args.kwargs or len(call_args.args) > 2


@pytest.mark.asyncio
async def test_lookup_ioc_found(mock_redis):
    """Test looking up an IOC that exists."""
    mock_redis.get.return_value = json.dumps({
        "ioc_type": "ip-dst",
        "value": "192.168.1.100",
        "misp_event_id": "4521",
        "misp_event_uuid": "abc-123",
        "misp_attribute_uuid": "def-456",
        "threat_level": "high",
        "tags": ["apt29"],
    })

    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        result = await cache.lookup_ioc(IOCType.IP_DST, "192.168.1.100")

        assert result is not None
        assert result["misp_event_id"] == "4521"
        assert result["threat_level"] == "high"


@pytest.mark.asyncio
async def test_lookup_ioc_not_found(mock_redis):
    """Test looking up an IOC that doesn't exist."""
    mock_redis.get.return_value = None

    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        result = await cache.lookup_ioc(IOCType.DOMAIN, "notfound.com")

        assert result is None


@pytest.mark.asyncio
async def test_bulk_store_iocs():
    """Test storing multiple IOCs at once."""
    # Pipeline needs to be a regular mock (not async) because pipeline() is sync
    mock_pipeline = MagicMock()
    mock_pipeline.execute = AsyncMock()

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipeline

    records = [
        IOCRecord(
            ioc_type=IOCType.IP_DST,
            value="1.2.3.4",
            misp_event_id="1",
            misp_event_uuid="u1",
            misp_attribute_uuid="a1",
            threat_level="high",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
        IOCRecord(
            ioc_type=IOCType.DOMAIN,
            value="evil.com",
            misp_event_id="2",
            misp_event_uuid="u2",
            misp_attribute_uuid="a2",
            threat_level="medium",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
    ]

    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        count = await cache.bulk_store_iocs(records)

        assert count == 2
        assert mock_pipeline.set.call_count == 2


@pytest.mark.asyncio
async def test_bulk_lookup_iocs(mock_redis):
    """Test looking up multiple IOCs at once."""
    mock_redis.mget.return_value = [
        json.dumps({"misp_event_id": "1", "threat_level": "high"}),
        None,  # Second one not found
        json.dumps({"misp_event_id": "3", "threat_level": "low"}),
    ]

    lookups = [
        (IOCType.IP_DST, "1.2.3.4"),
        (IOCType.DOMAIN, "notfound.com"),
        (IOCType.SHA256, "abc123"),
    ]

    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        results = await cache.bulk_lookup_iocs(lookups)

        assert len(results) == 3
        assert results[0] is not None
        assert results[1] is None
        assert results[2] is not None


@pytest.mark.asyncio
async def test_clear_all_iocs(mock_redis):
    """Test clearing all IOCs from cache."""
    mock_redis.keys.return_value = [
        "chad:ioc:ip-dst:1.2.3.4",
        "chad:ioc:domain:evil.com",
    ]
    mock_redis.delete.return_value = 2

    with patch("app.services.ti.ioc_cache.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        cache = IOCCache()
        count = await cache.clear_all_iocs()

        assert count == 2
        mock_redis.keys.assert_called_with("chad:ioc:*")
