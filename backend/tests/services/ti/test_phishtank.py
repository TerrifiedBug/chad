"""Tests for PhishTank Threat Intelligence client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.base import TIIndicatorType, TIRiskLevel
from app.services.ti.phishtank import PhishTankClient


@pytest.fixture
def phishtank_client():
    """Create a PhishTank client for testing."""
    return PhishTankClient(api_key=None)


@pytest.fixture
def phishtank_client_with_key():
    """Create a PhishTank client with API key for testing."""
    return PhishTankClient(api_key="test-api-key")


@pytest.mark.asyncio
async def test_phishtank_lookup_url_verified(phishtank_client):
    """Test URL lookup when found and verified in PhishTank."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "in_database": True,
        "verified": True,
        "phish_detail_url": "https://phishtank.com/phish_detail.php?phish_id=12345",
        "submit_time": "2024-01-01T00:00:00Z",
        "url": "http://evil.com/phishing"
    }

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.lookup_url("http://evil.com/phishing")

        assert result.success is True
        assert result.source == "phishtank"
        assert result.indicator == "http://evil.com/phishing"
        assert result.indicator_type == TIIndicatorType.URL
        assert result.risk_level == TIRiskLevel.CRITICAL  # Verified
        assert result.malicious_count == 1
        assert "phishing" in result.categories
        assert "verified" in result.tags
        assert result.first_seen == "2024-01-01T00:00:00Z"


@pytest.mark.asyncio
async def test_phishtank_lookup_url_unverified(phishtank_client):
    """Test URL lookup when found but unverified in PhishTank."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "in_database": True,
        "verified": False,
        "phish_detail_url": "https://phishtank.com/phish_detail.php?phish_id=67890",
        "submit_time": "2024-01-02T00:00:00Z",
        "url": "http://suspicious.com/login"
    }

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.lookup_url("http://suspicious.com/login")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.HIGH  # Unverified but in database
        assert result.malicious_count == 1
        assert "unverified" in result.tags


@pytest.mark.asyncio
async def test_phishtank_lookup_url_not_found(phishtank_client):
    """Test URL lookup when not found in PhishTank."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "in_database": False,
        "url": "http://legitimate.com"
    }

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.lookup_url("http://legitimate.com")

        assert result.success is True
        assert result.risk_level == TIRiskLevel.UNKNOWN
        assert result.malicious_count == 0
        assert result.categories == []


@pytest.mark.asyncio
async def test_phishtank_lookup_ip_not_supported(phishtank_client):
    """Test that IP lookups return not supported error."""
    result = await phishtank_client.lookup_ip("1.2.3.4")

    assert result.success is False
    assert "not supported" in result.error.lower()


@pytest.mark.asyncio
async def test_phishtank_lookup_domain_not_supported(phishtank_client):
    """Test that domain lookups return not supported error."""
    result = await phishtank_client.lookup_domain("evil.com")

    assert result.success is False
    assert "not supported" in result.error.lower()


@pytest.mark.asyncio
async def test_phishtank_lookup_hash_not_supported(phishtank_client):
    """Test that hash lookups return not supported error."""
    result = await phishtank_client.lookup_hash(
        "44d88612fea8a8f36de82e1278abb02fbb7c905b",
        TIIndicatorType.HASH_SHA256
    )

    assert result.success is False
    assert "not supported" in result.error.lower()


@pytest.mark.asyncio
async def test_phishtank_test_connection_success(phishtank_client):
    """Test successful connection to PhishTank."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"in_database": False}

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.test_connection()

        assert result is True


@pytest.mark.asyncio
async def test_phishtank_test_connection_failure(phishtank_client):
    """Test failed connection to PhishTank."""
    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Connection failed")

        result = await phishtank_client.test_connection()

        assert result is False


@pytest.mark.asyncio
async def test_phishtank_lookup_error_handling(phishtank_client):
    """Test error handling in PhishTank lookups."""
    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("API error")

        result = await phishtank_client.lookup_url("http://test.com")

        assert result.success is False
        assert result.error == "API error"


def test_phishtank_risk_level_calculation(phishtank_client):
    """Test risk level calculation based on verification status."""
    # Verified URLs are critical
    assert phishtank_client._calculate_risk_level(True) == TIRiskLevel.CRITICAL
    # Unverified URLs are still high risk
    assert phishtank_client._calculate_risk_level(False) == TIRiskLevel.HIGH


def test_phishtank_client_initialization():
    """Test PhishTank client initialization."""
    # Without API key
    client = PhishTankClient(api_key=None)
    assert client.api_key is None
    assert client.source_name == "phishtank"

    # With API key
    client_with_key = PhishTankClient(api_key="test-key", timeout=15)
    assert client_with_key.api_key == "test-key"
    assert client_with_key.timeout == 15


@pytest.mark.asyncio
async def test_phishtank_close(phishtank_client):
    """Test closing the PhishTank client."""
    with patch.object(phishtank_client._client, 'aclose', new_callable=AsyncMock) as mock_aclose:
        await phishtank_client.close()
        mock_aclose.assert_called_once()


@pytest.mark.asyncio
async def test_phishtank_api_key_included_in_request(phishtank_client_with_key):
    """Test that API key is included in request when provided."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "in_database": False,
        "url": "http://test.com"
    }

    with patch.object(phishtank_client_with_key._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        await phishtank_client_with_key.lookup_url("http://test.com")

        # Verify that the API key was included in params
        call_args = mock_get.call_args
        assert call_args[1]["params"]["app_key"] == "test-api-key"


@pytest.mark.asyncio
async def test_phishtank_url_only_supported_type(phishtank_client):
    """Test that only URL lookups are supported."""
    assert TIIndicatorType.URL in phishtank_client.supported_types
    assert TIIndicatorType.IP not in phishtank_client.supported_types
    assert TIIndicatorType.DOMAIN not in phishtank_client.supported_types
    assert TIIndicatorType.HASH_MD5 not in phishtank_client.supported_types
    assert TIIndicatorType.HASH_SHA1 not in phishtank_client.supported_types
    assert TIIndicatorType.HASH_SHA256 not in phishtank_client.supported_types


@pytest.mark.asyncio
async def test_phishtank_risk_score_calculation(phishtank_client):
    """Test risk score calculation."""
    # Verified URL = 100
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "in_database": True,
        "verified": True,
        "url": "http://test.com"
    }

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.lookup_url("http://test.com")
        assert result.risk_score == 100.0

    # Unverified URL = 75
    mock_response.json.return_value = {
        "in_database": True,
        "verified": False,
        "url": "http://test.com"
    }

    with patch.object(phishtank_client._client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await phishtank_client.lookup_url("http://test.com")
        assert result.risk_score == 75.0
