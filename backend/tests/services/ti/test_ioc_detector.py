"""Tests for IOC detector service."""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.ti.ioc_detector import IOCDetector, IOCMatch
from app.services.ti.ioc_types import IOCType


@pytest.fixture
def sample_field_mappings():
    """Sample IOC field mappings."""
    return {
        "ip-dst": ["destination.ip", "winlog.event_data.DestinationIp"],
        "ip-src": ["source.ip"],
        "domain": ["dns.question.name"],
        "md5": ["file.hash.md5"],
        "sha256": ["file.hash.sha256"],
        "url": ["url.full"],
    }


@pytest.fixture
def sample_log():
    """Sample log document."""
    return {
        "@timestamp": "2026-02-03T20:00:00Z",
        "destination.ip": "192.168.1.100",
        "source.ip": "10.0.0.1",
        "dns.question.name": "example.com",
    }


@pytest.mark.asyncio
async def test_detect_iocs_finds_match(sample_field_mappings, sample_log):
    """Test IOC detection finds a matching IP."""
    mock_cache = AsyncMock()
    # Only 3 lookups made: ip-dst (destination.ip), ip-src (source.ip), domain (dns.question.name)
    mock_cache.bulk_lookup_iocs.return_value = [
        {"misp_event_id": "4521", "threat_level": "high", "tags": ["apt29"]},  # ip-dst match
        None,  # ip-src no match
        None,  # domain no match
    ]

    with patch("app.services.ti.ioc_detector.IOCCache", return_value=mock_cache):
        detector = IOCDetector()
        matches = await detector.detect_iocs(sample_log, sample_field_mappings)

        assert len(matches) == 1
        assert matches[0].ioc_type == IOCType.IP_DST
        assert matches[0].value == "192.168.1.100"
        assert matches[0].misp_event_id == "4521"
        assert matches[0].threat_level == "high"


@pytest.mark.asyncio
async def test_detect_iocs_no_matches(sample_field_mappings, sample_log):
    """Test IOC detection with no matches."""
    mock_cache = AsyncMock()
    # 3 lookups made but all return None
    mock_cache.bulk_lookup_iocs.return_value = [None, None, None]

    with patch("app.services.ti.ioc_detector.IOCCache", return_value=mock_cache):
        detector = IOCDetector()
        matches = await detector.detect_iocs(sample_log, sample_field_mappings)

        assert matches == []


@pytest.mark.asyncio
async def test_detect_iocs_multiple_matches(sample_field_mappings):
    """Test IOC detection with multiple matches."""
    log = {
        "destination.ip": "192.168.1.100",
        "dns.question.name": "evil.com",
    }

    mock_cache = AsyncMock()
    # Only 2 lookups made: ip-dst (destination.ip), domain (dns.question.name)
    mock_cache.bulk_lookup_iocs.return_value = [
        {"misp_event_id": "100", "threat_level": "high"},  # ip-dst
        {"misp_event_id": "200", "threat_level": "medium"},  # domain
    ]

    with patch("app.services.ti.ioc_detector.IOCCache", return_value=mock_cache):
        detector = IOCDetector()
        matches = await detector.detect_iocs(log, sample_field_mappings)

        assert len(matches) == 2


@pytest.mark.asyncio
async def test_detect_iocs_extracts_nested_field(sample_field_mappings):
    """Test IOC detection extracts nested fields."""
    log = {
        "winlog": {
            "event_data": {
                "DestinationIp": "10.20.30.40"
            }
        }
    }

    mock_cache = AsyncMock()
    mock_cache.bulk_lookup_iocs.return_value = [
        {"misp_event_id": "999", "threat_level": "high"},  # Nested field match
    ]

    with patch("app.services.ti.ioc_detector.IOCCache", return_value=mock_cache):
        detector = IOCDetector()
        matches = await detector.detect_iocs(log, sample_field_mappings)

        assert len(matches) == 1
        assert matches[0].value == "10.20.30.40"


def test_ioc_match_dataclass():
    """Test IOCMatch dataclass."""
    match = IOCMatch(
        ioc_type=IOCType.DOMAIN,
        value="evil.com",
        field_name="dns.question.name",
        misp_event_id="123",
        misp_event_uuid="uuid-123",
        misp_attribute_uuid="attr-456",
        threat_level="high",
        tags=["phishing"],
    )
    assert match.ioc_type == IOCType.DOMAIN
    assert match.value == "evil.com"
