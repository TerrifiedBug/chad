"""Tests for abuse.ch Threat Intelligence client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.abuse_ch import AbuseCHClient
from app.services.ti.base import TIIndicatorType, TIRiskLevel


@pytest.fixture
def abuse_ch_client():
    """Create an abuse.ch client for testing."""
    return AbuseCHClient(api_key=None)


@pytest.mark.asyncio
async def test_abuse_ch_lookup_ip_found(abuse_ch_client):
    """Test IP lookup when found in URLhaus."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "urls": [
            {
                "url": "http://evil.com/malware.exe",
                "threat_type": "malware_download",
                "firstseen": "2024-01-01",
                "lastseen": "2024-01-15"
            },
            {
                "url": "http://evil.com/payload.dll",
                "threat_type": "malware_download",
                "firstseen": "2024-01-02",
            }
        ]
    }

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.lookup_ip("93.184.216.34")

        assert result.success is True
        assert result.source == "abuse_ch"
        assert result.indicator == "93.184.216.34"
        assert result.indicator_type == TIIndicatorType.IP
        assert result.risk_level == TIRiskLevel.HIGH  # 2 URLs
        assert result.malicious_count == 2
        assert "malware_download" in result.categories
        assert result.first_seen == "2024-01-01"


@pytest.mark.asyncio
async def test_abuse_ch_lookup_ip_not_found(abuse_ch_client):
    """Test IP lookup when not found in URLhaus."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "no_results"
    }

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.lookup_ip("1.2.3.4")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.UNKNOWN
        assert result.malicious_count == 0


@pytest.mark.asyncio
async def test_abuse_ch_lookup_domain_found(abuse_ch_client):
    """Test domain lookup when found in URLhaus."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "urls": [
            {
                "url": "http://evil.com/phishing",
                "threat_type": "phishing",
                "firstseen": "2024-01-01",
                "lastseen": "2024-01-20"
            }
        ]
    }

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.lookup_domain("evil.com")

        assert result.success is True
        assert result.indicator == "evil.com"
        assert result.indicator_type == TIIndicatorType.DOMAIN
        assert result.risk_level == TIRiskLevel.MEDIUM  # 1 URL
        assert result.malicious_count == 1
        assert "phishing" in result.categories


@pytest.mark.asyncio
async def test_abuse_ch_lookup_url_found(abuse_ch_client):
    """Test URL lookup when found in URLhaus."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "urls": [
            {
                "url": "http://malware.com/dropper",
                "threat_type": "botnet_c2",
                "firstseen": "2024-01-01",
                "lastseen": "2024-01-25"
            }
        ]
    }

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.lookup_url("http://malware.com/dropper")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.MEDIUM
        assert "botnet_c2" in result.categories


@pytest.mark.asyncio
async def test_abuse_ch_lookup_multiple_urls_high_risk(abuse_ch_client):
    """Test lookup with multiple malicious URLs results in critical risk."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "urls": [
            {"url": "http://evil.com/1", "threat_type": "malware_download"},
            {"url": "http://evil.com/2", "threat_type": "malware_download"},
            {"url": "http://evil.com/3", "threat_type": "phishing"},
            {"url": "http://evil.com/4", "threat_type": "botnet_c2"},
            {"url": "http://evil.com/5", "threat_type": "exploit_kit"},
        ]
    }

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.lookup_ip("93.184.216.34")

        assert result.risk_level == TIRiskLevel.CRITICAL  # 5+ URLs = CRITICAL
        assert result.malicious_count == 5
        assert len(result.categories) == 4  # 4 unique threat types


@pytest.mark.asyncio
async def test_abuse_ch_lookup_hash_not_supported(abuse_ch_client):
    """Test that hash lookups return not supported error."""
    result = await abuse_ch_client.lookup_hash(
        "44d88612fea8a8f36de82e1278abb02fbb7c905b",
        TIIndicatorType.HASH_MD5
    )

    assert result.success is False
    assert "not supported" in result.error.lower()


@pytest.mark.asyncio
async def test_abuse_ch_test_connection_success(abuse_ch_client):
    """Test successful connection to abuse.ch."""
    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        result = await abuse_ch_client.test_connection()

        assert result is True


@pytest.mark.asyncio
async def test_abuse_ch_test_connection_failure(abuse_ch_client):
    """Test failed connection to abuse.ch raises exception."""
    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("Connection failed")

        with pytest.raises(Exception) as exc_info:
            await abuse_ch_client.test_connection()

        assert "Connection failed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_abuse_ch_lookup_error_handling(abuse_ch_client):
    """Test error handling in abuse.ch lookups."""
    with patch.object(abuse_ch_client._client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("API error")

        result = await abuse_ch_client.lookup_ip("1.2.3.4")

        assert result.success is False
        assert result.error == "API error"


def test_abuse_ch_risk_level_calculation(abuse_ch_client):
    """Test risk level calculation based on URL count."""
    # Any match is malicious
    assert abuse_ch_client._calculate_risk_level(0, []) == TIRiskLevel.UNKNOWN
    assert abuse_ch_client._calculate_risk_level(1, ["malware"]) == TIRiskLevel.MEDIUM
    assert abuse_ch_client._calculate_risk_level(2, ["malware"]) == TIRiskLevel.HIGH
    assert abuse_ch_client._calculate_risk_level(5, ["malware"]) == TIRiskLevel.CRITICAL


def test_abuse_ch_threat_type_extraction(abuse_ch_client):
    """Test extraction of unique threat types."""
    urls = [
        {"threat_type": "malware_download"},
        {"threat_type": "malware_download"},
        {"threat_type": "phishing"},
        {"threat_type": "botnet_c2"},
    ]

    threat_types = abuse_ch_client._extract_threat_types(urls)

    assert len(threat_types) == 3  # 3 unique types
    assert "malware_download" in threat_types
    assert "phishing" in threat_types
    assert "botnet_c2" in threat_types


def test_abuse_ch_client_initialization():
    """Test abuse.ch client initialization."""
    # Without API key (URLhaus is open)
    client = AbuseCHClient(api_key=None)
    assert client.api_key is None
    assert client.source_name == "abuse_ch"

    # With API key
    client_with_key = AbuseCHClient(api_key="test-key", timeout=15)
    assert client_with_key.api_key == "test-key"
    assert client_with_key.timeout == 15


@pytest.mark.asyncio
async def test_abuse_ch_close(abuse_ch_client):
    """Test closing the abuse.ch client."""
    with patch.object(abuse_ch_client._client, 'aclose', new_callable=AsyncMock) as mock_aclose:
        await abuse_ch_client.close()
        mock_aclose.assert_called_once()
