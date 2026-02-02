"""Tests for MISP Threat Intelligence client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.base import TIIndicatorType, TIRiskLevel
from app.services.ti.misp import MISPClient


@pytest.fixture
def misp_client():
    """Create a MISP client for testing."""
    return MISPClient(
        api_key="test-api-key",
        instance_url="https://misp.example.com"
    )


@pytest.mark.asyncio
async def test_misp_lookup_ip_found(misp_client):
    """Test IP lookup when found in MISP."""
    # Mock the HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Attribute": [
            {
                "event_id": 123,
                "distribution": 3,
                "category": "Network activity",
                "timestamp": 1234567890
            },
            {
                "event_id": 456,
                "distribution": 2,
                "category": "Malware",
                "timestamp": 1234567891
            }
        ]
    }

    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await misp_client.lookup_ip("93.184.216.34")

        assert result.success is True
        assert result.source == "misp"
        assert result.indicator == "93.184.216.34"
        assert result.indicator_type == TIIndicatorType.IP
        assert result.risk_level == TIRiskLevel.HIGH  # distribution >= 3
        assert result.malicious_count == 2
        assert "Network activity" in result.categories
        assert "Malware" in result.categories


@pytest.mark.asyncio
async def test_misp_lookup_ip_not_found(misp_client):
    """Test IP lookup when not found in MISP."""
    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response
        mock_post.raise_for_status = MagicMock(side_effect=Exception("404"))

        result = await misp_client.lookup_ip("1.2.3.4")

        assert result.success is True  # Not found is not an error
        assert result.risk_level == TIRiskLevel.UNKNOWN
        assert result.malicious_count == 0


@pytest.mark.asyncio
async def test_misp_lookup_domain_found(misp_client):
    """Test domain lookup when found in MISP."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Attribute": [
            {
                "event_id": 789,
                "distribution": 1,
                "category": "Fraud",
                "Tag": [{"name": "phishing"}, {"name": "credential-theft"}]
            }
        ]
    }

    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await misp_client.lookup_domain("evil.com")

        assert result.success is True
        assert result.indicator == "evil.com"
        assert result.indicator_type == TIIndicatorType.DOMAIN
        assert result.risk_level == TIRiskLevel.LOW  # 1 event
        assert "phishing" in result.tags
        assert "credential-theft" in result.tags


@pytest.mark.asyncio
async def test_misp_lookup_url_found(misp_client):
    """Test URL lookup when found in MISP."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Attribute": [
            {
                "event_id": 999,
                "distribution": 4,
                "category": "Payload delivery"
            }
        ]
    }

    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await misp_client.lookup_url("http://evil.com/malware")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.HIGH  # distribution >= 3


@pytest.mark.asyncio
async def test_misp_lookup_hash_sha256_found(misp_client):
    """Test SHA256 hash lookup when found in MISP."""
    hash_value = "44d88612fea8a8f36de82e1278abb02fbb7c905b6a8a7d0d0f4d5b2d1f3e9a7c"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Attribute": [
            {
                "event_id": 111,
                "distribution": 2,
                "category": "Artifacts dropped",
                "Tag": [{"name": "ransomware"}]
            },
            {
                "event_id": 222,
                "distribution": 2,
                "category": "Malware sample"
            }
        ]
    }

    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await misp_client.lookup_hash(hash_value, TIIndicatorType.HASH_SHA256)

        assert result.success is True
        assert result.indicator == hash_value
        assert result.indicator_type == TIIndicatorType.HASH_SHA256
        assert result.risk_level == TIRiskLevel.MEDIUM  # 2 events, distribution 2
        assert result.malicious_count == 2
        assert "ransomware" in result.tags


@pytest.mark.asyncio
async def test_misp_test_connection_success(misp_client):
    """Test successful connection to MISP."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"Event": {"id": "123"}}]

    with patch.object(misp_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await misp_client.test_connection()

        assert result is True


@pytest.mark.asyncio
async def test_misp_test_connection_failure(misp_client):
    """Test failed connection to MISP."""
    with patch.object(misp_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Connection failed")

        result = await misp_client.test_connection()

        assert result is False


@pytest.mark.asyncio
async def test_misp_lookup_error_handling(misp_client):
    """Test error handling in MISP lookups."""
    with patch.object(misp_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("API error")

        result = await misp_client.lookup_ip("1.2.3.4")

        assert result.success is False
        assert result.error == "API error"


def test_misp_indicator_type_mapping(misp_client):
    """Test mapping of indicator types to MISP attribute types."""
    assert misp_client._map_indicator_type(TIIndicatorType.DOMAIN) == "domain"
    assert misp_client._map_indicator_type(TIIndicatorType.IP) == "ip-dst"
    assert misp_client._map_indicator_type(TIIndicatorType.URL) == "url"
    assert misp_client._map_indicator_type(TIIndicatorType.HASH_MD5) == "md5"
    assert misp_client._map_indicator_type(TIIndicatorType.HASH_SHA1) == "sha1"
    assert misp_client._map_indicator_type(TIIndicatorType.HASH_SHA256) == "sha256"


def test_misp_risk_level_calculation(misp_client):
    """Test risk level calculation based on distribution and event count."""
    # High risk: high distribution or many events
    assert misp_client._calculate_risk_level(3, 1) == TIRiskLevel.HIGH
    assert misp_client._calculate_risk_level(1, 5) == TIRiskLevel.HIGH

    # Medium risk: moderate distribution or multiple events
    assert misp_client._calculate_risk_level(2, 1) == TIRiskLevel.MEDIUM
    assert misp_client._calculate_risk_level(1, 2) == TIRiskLevel.MEDIUM

    # Low risk: single event
    assert misp_client._calculate_risk_level(1, 1) == TIRiskLevel.LOW

    # Unknown: no events
    assert misp_client._calculate_risk_level(0, 0) == TIRiskLevel.UNKNOWN


def test_misp_client_initialization():
    """Test MISP client initialization."""
    client = MISPClient(
        api_key="test-key",
        instance_url="https://misp.example.com/",
        timeout=15
    )

    assert client.api_key == "test-key"
    assert client.instance_url == "https://misp.example.com"  # Trailing slash removed
    assert client.timeout == 15
    assert client.source_name == "misp"


@pytest.mark.asyncio
async def test_misp_close(misp_client):
    """Test closing the MISP client."""
    with patch.object(misp_client._client, 'aclose', new_callable=AsyncMock) as mock_aclose:
        await misp_client.close()
        mock_aclose.assert_called_once()
