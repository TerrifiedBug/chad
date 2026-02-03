"""VirusTotal Threat Intelligence client."""

import base64
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

# VirusTotal API base URL
VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient(TIClient):
    """VirusTotal API client for threat intelligence lookups."""

    source_name = "virustotal"
    supported_types = [
        TIIndicatorType.IP,
        TIIndicatorType.DOMAIN,
        TIIndicatorType.URL,
        TIIndicatorType.HASH_MD5,
        TIIndicatorType.HASH_SHA1,
        TIIndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str, timeout: int = 30):
        """Initialize the VirusTotal client.

        Args:
            api_key: VirusTotal API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=VT_API_BASE,
            headers={"x-apikey": api_key},
            timeout=timeout,
        )

    async def _make_request(self, endpoint: str) -> dict[str, Any] | None:
        """Make a request to the VirusTotal API.

        Args:
            endpoint: API endpoint path.

        Returns:
            JSON response data or None on error.
        """
        try:
            response = await self._client.get(endpoint)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None  # Not found is not an error for lookups
            logger.error("VirusTotal API error: %s", e.response.status_code)
            raise
        except Exception as e:
            logger.error("VirusTotal request error: %s", e)
            raise

    def _calculate_risk_level(self, malicious: int, suspicious: int, total: int) -> TIRiskLevel:
        """Calculate risk level based on detection counts.

        Args:
            malicious: Number of malicious detections.
            suspicious: Number of suspicious detections.
            total: Total number of engines.

        Returns:
            Risk level based on detection ratio.
        """
        if total == 0:
            return TIRiskLevel.UNKNOWN

        # Calculate detection ratio
        ratio = (malicious + suspicious * 0.5) / total

        if malicious >= 10 or ratio >= 0.25:
            return TIRiskLevel.CRITICAL
        elif malicious >= 5 or ratio >= 0.15:
            return TIRiskLevel.HIGH
        elif malicious >= 2 or ratio >= 0.05:
            return TIRiskLevel.MEDIUM
        elif malicious >= 1 or suspicious >= 1:
            return TIRiskLevel.LOW
        else:
            return TIRiskLevel.SAFE

    def _calculate_risk_score(self, malicious: int, suspicious: int, total: int) -> float:
        """Calculate normalized risk score (0-100).

        Args:
            malicious: Number of malicious detections.
            suspicious: Number of suspicious detections.
            total: Total number of engines.

        Returns:
            Risk score from 0-100.
        """
        if total == 0:
            return 0.0

        # Weighted score: malicious = 1.0, suspicious = 0.5
        return min(100.0, ((malicious + suspicious * 0.5) / total) * 100 * 4)

    def _extract_categories(self, data: dict[str, Any]) -> list[str]:
        """Extract categories from VT response.

        Args:
            data: VirusTotal response data.

        Returns:
            List of category strings.
        """
        categories = []
        attrs = data.get("attributes", {})

        # From categories field
        if "categories" in attrs:
            categories.extend(attrs["categories"].values())

        # From popular threat classification
        threat_names = attrs.get("popular_threat_classification", {})
        if "suggested_threat_label" in threat_names:
            categories.append(threat_names["suggested_threat_label"])

        return list(set(categories))

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in VirusTotal."""
        try:
            response = await self._make_request(f"/ip_addresses/{ip}")

            if not response:
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            data = response.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(malicious, suspicious, total),
                risk_score=self._calculate_risk_score(malicious, suspicious, total),
                categories=self._extract_categories(data),
                malicious_count=malicious,
                total_count=total,
                country=attrs.get("country"),
                asn=str(attrs.get("asn", "")) if attrs.get("asn") else None,
                as_owner=attrs.get("as_owner"),
                raw_response=response,
            )

        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain in VirusTotal."""
        try:
            response = await self._make_request(f"/domains/{domain}")

            if not response:
                return TILookupResult(
                    source=self.source_name,
                    indicator=domain,
                    indicator_type=TIIndicatorType.DOMAIN,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            data = response.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            return TILookupResult(
                source=self.source_name,
                indicator=domain,
                indicator_type=TIIndicatorType.DOMAIN,
                success=True,
                risk_level=self._calculate_risk_level(malicious, suspicious, total),
                risk_score=self._calculate_risk_score(malicious, suspicious, total),
                categories=self._extract_categories(data),
                malicious_count=malicious,
                total_count=total,
                first_seen=attrs.get("creation_date"),
                raw_response=response,
            )

        except Exception as e:
            return self._create_error_result(domain, TIIndicatorType.DOMAIN, str(e))

    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Look up a file hash in VirusTotal."""
        try:
            response = await self._make_request(f"/files/{hash_value}")

            if not response:
                return TILookupResult(
                    source=self.source_name,
                    indicator=hash_value,
                    indicator_type=hash_type,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            data = response.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            # Extract tags from various sources
            tags = []
            if "tags" in attrs:
                tags.extend(attrs["tags"])
            if "type_tags" in attrs:
                tags.extend(attrs["type_tags"])

            return TILookupResult(
                source=self.source_name,
                indicator=hash_value,
                indicator_type=hash_type,
                success=True,
                risk_level=self._calculate_risk_level(malicious, suspicious, total),
                risk_score=self._calculate_risk_score(malicious, suspicious, total),
                categories=self._extract_categories(data),
                tags=list(set(tags)),
                malicious_count=malicious,
                total_count=total,
                first_seen=attrs.get("first_submission_date"),
                last_seen=attrs.get("last_analysis_date"),
                raw_response=response,
            )

        except Exception as e:
            return self._create_error_result(hash_value, hash_type, str(e))

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in VirusTotal."""
        try:
            # VT requires URL to be base64 encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            response = await self._make_request(f"/urls/{url_id}")

            if not response:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            data = response.get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            return TILookupResult(
                source=self.source_name,
                indicator=url,
                indicator_type=TIIndicatorType.URL,
                success=True,
                risk_level=self._calculate_risk_level(malicious, suspicious, total),
                risk_score=self._calculate_risk_score(malicious, suspicious, total),
                categories=self._extract_categories(data),
                malicious_count=malicious,
                total_count=total,
                first_seen=attrs.get("first_submission_date"),
                last_seen=attrs.get("last_analysis_date"),
                raw_response=response,
            )

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def test_connection(self) -> bool:
        """Test the VirusTotal API connection."""
        try:
            # Try to get user info as a simple API test
            response = await self._client.get("/users/me")
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                raise Exception("Invalid API key - authentication failed")
            elif response.status_code == 403:
                raise Exception("API key lacks required permissions")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except httpx.ConnectError:
            raise Exception("Could not connect to VirusTotal API - check network")
        except httpx.TimeoutException:
            raise Exception("Connection timed out - VirusTotal may be slow or unreachable")
        except Exception as e:
            if "Invalid API key" in str(e) or "API returned" in str(e) or "Could not connect" in str(e) or "timed out" in str(e):
                raise  # Re-raise our descriptive errors
            raise Exception(f"Connection failed: {e}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
