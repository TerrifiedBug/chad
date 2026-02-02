"""Tests for AlienVault OTX Threat Intelligence client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.alienvault_otx import AlienVaultOTXClient
from app.services.ti.base import TIIndicatorType, TIRiskLevel


@pytest.fixture
def otx_client():
    """Create an AlienVault OTX client for testing."""
    return AlienVaultOTXClient(api_key="test-api-key")


@pytest.fixture
def sample_pulse_data():
    """Sample pulse data from OTX."""
    return {
        "count": 2,
        "pulses": [
            {
                "id": "12345",
                "name": "Malicious Campaign A",
                "tags": ["malware", "trojan", "apt"],
                "created": "2024-01-01T00:00:00Z"
            },
            {
                "id": "67890",
                "name": "Phishing Kit B",
                "tags": ["phishing", "credential-theft"],
                "created": "2024-01-02T00:00:00Z"
            }
        ]
    }


@pytest.mark.asyncio
async def test_otx_lookup_ip_found(otx_client, sample_pulse_data):
    """Test IP lookup when found in OTX."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "reputation": {
            "reputation": 70
        },
        "pulse_info": sample_pulse_data,
        "whois": "Example Corp"
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_ip("93.184.216.34")

        assert result.success is True
        assert result.source == "alienvault_otx"
        assert result.indicator == "93.184.216.34"
        assert result.indicator_type == TIIndicatorType.IP
        assert result.risk_level == TIRiskLevel.MEDIUM  # 2 pulses
        assert result.malicious_count == 2
        assert "malware" in result.tags
        assert "phishing" in result.tags


@pytest.mark.asyncio
async def test_otx_lookup_ip_not_found(otx_client):
    """Test IP lookup when not found in OTX."""
    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("404")

        result = await otx_client.lookup_ip("1.2.3.4")

        assert result.success is False
        assert "404" in result.error


@pytest.mark.asyncio
async def test_otx_lookup_domain_found(otx_client, sample_pulse_data):
    """Test domain lookup when found in OTX."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": sample_pulse_data,
        "whois": "Domain Registration info"
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_domain("evil.com")

        assert result.success is True
        assert result.indicator == "evil.com"
        assert result.indicator_type == TIIndicatorType.DOMAIN
        assert result.risk_level == TIRiskLevel.MEDIUM  # 2 pulses
        assert result.malicious_count == 2


@pytest.mark.asyncio
async def test_otx_lookup_url_found(otx_client):
    """Test URL lookup when found in OTX."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "name": "Malicious URL",
                    "tags": ["malware_distribution"]
                }
            ]
        }
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_url("http://evil.com/malware")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.LOW  # 1 pulse


@pytest.mark.asyncio
async def test_otx_lookup_hash_found(otx_client):
    """Test hash lookup when found in OTX."""
    hash_value = "44d88612fea8a8f36de82e1278abb02fbb7c905b"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 3,
            "pulses": [
                {"name": "Ransomware X", "tags": ["ransomware"]},
                {"name": "APT Campaign", "tags": ["apt"]},
                {"name": "Trojan Y", "tags": ["trojan"]},
            ]
        },
        "analysis": {
            "results": {
                "Engine1": {"malware": True},
                "Engine2": {"malware": False},
            }
        }
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_hash(hash_value, TIIndicatorType.HASH_SHA256)

        assert result.success is True
        assert result.indicator == hash_value
        assert result.indicator_type == TIIndicatorType.HASH_SHA256
        assert result.risk_level == TIRiskLevel.MEDIUM  # 3 pulses
        assert result.malicious_count == 3


@pytest.mark.asyncio
async def test_otx_high_pulse_count_critical_risk(otx_client):
    """Test that many pulses results in critical risk."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 12,
            "pulses": [{"name": f"Pulse {i}"} for i in range(12)]
        },
        "reputation": {}
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_ip("93.184.216.34")

        assert result.risk_level == TIRiskLevel.CRITICAL  # 10+ pulses


@pytest.mark.asyncio
async def test_otx_test_connection_success(otx_client):
    """Test successful connection to OTX."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"username": "testuser"}

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.test_connection()

        assert result is True


@pytest.mark.asyncio
async def test_otx_test_connection_failure(otx_client):
    """Test failed connection to OTX."""
    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Authentication failed")

        result = await otx_client.test_connection()

        assert result is False


@pytest.mark.asyncio
async def test_otx_lookup_error_handling(otx_client):
    """Test error handling in OTX lookups."""
    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("API error")

        result = await otx_client.lookup_ip("1.2.3.4")

        assert result.success is False
        assert result.error == "API error"


def test_otx_risk_level_calculation(otx_client):
    """Test risk level calculation based on pulse count."""
    assert otx_client._calculate_risk_level(0) == TIRiskLevel.UNKNOWN
    assert otx_client._calculate_risk_level(1) == TIRiskLevel.LOW
    assert otx_client._calculate_risk_level(2) == TIRiskLevel.MEDIUM
    assert otx_client._calculate_risk_level(5) == TIRiskLevel.HIGH
    assert otx_client._calculate_risk_level(10) == TIRiskLevel.CRITICAL
    assert otx_client._calculate_risk_level(15) == TIRiskLevel.CRITICAL


def test_otx_pulse_info_extraction(otx_client):
    """Test extraction of pulse information from OTX response."""
    data = {
        "pulse_info": {
            "pulses": [
                {
                    "name": "Pulse A",
                    "tags": ["malware", "trojan"]
                },
                {
                    "name": "Pulse B",
                    "tags": ["phishing"]
                }
            ]
        }
    }

    pulse_count, tags, pulse_names = otx_client._extract_pulse_info(data)

    assert pulse_count == 2
    assert "malware" in tags
    assert "trojan" in tags
    assert "phishing" in tags
    assert "Pulse A" in pulse_names
    assert "Pulse B" in pulse_names


def test_otx_client_initialization():
    """Test OTX client initialization."""
    client = AlienVaultOTXClient(api_key="test-key", timeout=15)

    assert client.api_key == "test-key"
    assert client.timeout == 15
    assert client.source_name == "alienvault_otx"


@pytest.mark.asyncio
async def test_otx_close(otx_client):
    """Test closing the OTX client."""
    with patch.object(otx_client._client, 'aclose', new_callable=AsyncMock) as mock_aclose:
        await otx_client.close()
        mock_aclose.assert_called_once()


@pytest.mark.asyncio
async def test_otx_multiple_pulses_high_risk(otx_client):
    """Test that 7-9 pulses results in high risk."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 7,
            "pulses": [{"name": f"Pulse {i}"} for i in range(7)]
        }
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_domain("evil.com")

        assert result.risk_level == TIRiskLevel.HIGH
        assert result.malicious_count == 7


@pytest.mark.asyncio
async def test_otx_tag_deduplication(otx_client):
    """Test that duplicate tags are properly deduplicated."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "pulses": [
                {"name": "P1", "tags": ["malware", "trojan"]},
                {"name": "P2", "tags": ["malware", "apt"]},  # 'malware' duplicate
                {"name": "P3", "tags": ["trojan", "botnet"]},  # 'trojan' duplicate
            ]
        }
    }

    with patch.object(otx_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await otx_client.lookup_ip("1.2.3.4")

        # Check tags are deduplicated
        assert result.tags.count("malware") == 1
        assert result.tags.count("trojan") == 1
        assert "apt" in result.tags
        assert "botnet" in result.tags
