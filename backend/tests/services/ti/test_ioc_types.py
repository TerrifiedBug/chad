"""Tests for IOC data types."""

import pytest
from datetime import datetime, UTC

from app.services.ti.ioc_types import IOCType, IOCRecord


def test_ioc_type_enum_values():
    """Test IOC type enum has expected values."""
    assert IOCType.IP_DST.value == "ip-dst"
    assert IOCType.IP_SRC.value == "ip-src"
    assert IOCType.DOMAIN.value == "domain"
    assert IOCType.MD5.value == "md5"
    assert IOCType.SHA256.value == "sha256"
    assert IOCType.URL.value == "url"


def test_ioc_record_to_redis_key():
    """Test IOC record generates correct Redis key."""
    record = IOCRecord(
        ioc_type=IOCType.IP_DST,
        value="192.168.1.100",
        misp_event_id="4521",
        misp_event_uuid="abc-123",
        misp_attribute_uuid="def-456",
        threat_level="high",
        tags=["apt29", "tlp:amber"],
        expires_at=datetime(2026, 3, 1, tzinfo=UTC),
    )
    assert record.redis_key == "chad:ioc:ip-dst:192.168.1.100"


def test_ioc_record_to_dict():
    """Test IOC record serializes to dict for Redis storage."""
    record = IOCRecord(
        ioc_type=IOCType.DOMAIN,
        value="evil.com",
        misp_event_id="123",
        misp_event_uuid="uuid-123",
        misp_attribute_uuid="attr-456",
        threat_level="medium",
        tags=["phishing"],
        expires_at=datetime(2026, 3, 1, tzinfo=UTC),
    )
    d = record.to_dict()
    assert d["ioc_type"] == "domain"
    assert d["value"] == "evil.com"
    assert d["misp_event_id"] == "123"
    assert "tags" in d


def test_ioc_record_to_opensearch_doc():
    """Test IOC record generates OpenSearch document."""
    record = IOCRecord(
        ioc_type=IOCType.SHA256,
        value="abc123def456",
        misp_event_id="789",
        misp_event_uuid="event-uuid",
        misp_attribute_uuid="attr-uuid",
        misp_event_info="Malware campaign",
        threat_level="high",
        tags=["ransomware"],
        expires_at=datetime(2026, 3, 1, tzinfo=UTC),
    )
    doc = record.to_opensearch_doc()
    assert doc["indicator.type"] == "sha256"
    assert doc["indicator.value"] == "abc123def456"
    assert doc["misp.event_id"] == "789"
    assert doc["misp.event_info"] == "Malware campaign"
