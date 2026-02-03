"""PhishTank Threat Intelligence client.

PhishTank is a collaborative clearing house for data and information
about phishing on the Internet.
"""

import logging
from typing import Any

import httpx

from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)

logger = logging.getLogger(__name__)

# PhishTank API URL
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"


class PhishTankClient(TIClient):
    """PhishTank API client for phishing URL detection.

    PhishTank is a community-based phishing URL verification system.
    """

    source_name = "phishtank"
    supported_types = [
        TIIndicatorType.URL,
    ]

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        """Initialize the PhishTank client.

        Args:
            api_key: Optional PhishTank API key (recommended for rate limits).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            headers={
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _calculate_risk_level(self, verified: bool) -> TIRiskLevel:
        """Calculate risk level based on verification status.

        Args:
            verified: Whether the URL has been verified by PhishTank.

        Returns:
            Risk level assessment.
        """
        if verified:
            return TIRiskLevel.CRITICAL
        else:
            return TIRiskLevel.HIGH  # In database but not verified

    async def _check_url(self, url: str) -> dict[str, Any] | None:
        """Check a URL against PhishTank database.

        Args:
            url: URL to check.

        Returns:
            JSON response data or None on error.
        """
        try:
            params = {"url": url}
            if self.api_key:
                params["app_key"] = self.api_key

            response = await self._client.get(
                PHISHTANK_API_URL,
                params=params,
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error("PhishTank request error: %s", e)
            raise

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """IP lookups not supported by PhishTank."""
        return self._create_not_supported_result(ip, TIIndicatorType.IP)

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Domain lookups not supported by PhishTank."""
        return self._create_not_supported_result(domain, TIIndicatorType.DOMAIN)

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in PhishTank."""
        try:
            data = await self._check_url(url)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response={},
                )

            in_database = data.get("in_database", False)

            if not in_database:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    categories=[],
                    raw_response=data,
                )

            verified = data.get("verified", False)
            submit_time = data.get("submit_time")

            return TILookupResult(
                source=self.source_name,
                indicator=url,
                indicator_type=TIIndicatorType.URL,
                success=True,
                risk_level=self._calculate_risk_level(verified),
                risk_score=float(100 if verified else 75),
                categories=["phishing"],
                tags=["verified" if verified else "unverified"],
                malicious_count=1 if in_database else 0,
                total_count=1,
                first_seen=submit_time,
                last_seen=submit_time,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Hash lookups not supported by PhishTank."""
        return self._create_not_supported_result(hash_value, hash_type)

    async def test_connection(self) -> bool:
        """Test the connection to PhishTank.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            # Test with a known phishing URL
            response = await self._client.get(
                PHISHTANK_API_URL,
                params={"url": "http://evil.com"},
            )

            if response.status_code == 200:
                logger.info("PhishTank connection test successful")
                return True
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except httpx.ConnectError:
            raise Exception("Could not connect to PhishTank API - check network")
        except httpx.TimeoutException:
            raise Exception("Connection timed out")
        except Exception as e:
            if "API returned" in str(e) or "Could not connect" in str(e) or "Rate limit" in str(e):
                raise
            raise Exception(f"Connection failed: {e}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
