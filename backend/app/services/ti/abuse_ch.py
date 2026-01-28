"""abuse.ch Threat Intelligence client.

abuse.ch provides several threat intelligence feeds:
- URLhaus: Malware URL distribution network
- Feodo Tracker: C2 servers for various botnets
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

# abuse.ch API endpoints
URLHAUS_API = "https://urlhaus.abuse.ch/api/"


class AbuseCHClient(TIClient):
    """abuse.ch API client for threat intelligence lookups.

    URLhaus is a project from abuse.ch with the goal of sharing
    malicious URLs that are being used for malware distribution.
    """

    source_name = "abuse_ch"
    supported_types = [
        TIIndicatorType.DOMAIN,
        TIIndicatorType.IP,
        TIIndicatorType.URL,
    ]

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        """Initialize the abuse.ch client.

        Args:
            api_key: Optional API key (abuse.ch APIs are typically open).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=URLHAUS_API,
            headers={
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _calculate_risk_level(self, url_count: int, threat_types: list[str]) -> TIRiskLevel:
        """Calculate risk level based on URL count and threat types.

        Args:
            url_count: Number of malicious URLs found.
            threat_types: List of threat type categories.

        Returns:
            Risk level assessment.
        """
        # Any match in URLhaus is considered malicious
        if url_count >= 5:
            return TIRiskLevel.CRITICAL
        elif url_count >= 2:
            return TIRiskLevel.HIGH
        elif url_count == 1:
            return TIRiskLevel.MEDIUM
        else:
            return TIRiskLevel.UNKNOWN

    async def _query_urlhaus(self, ioc_type: TIIndicatorType, value: str) -> dict[str, Any] | None:
        """Query URLhaus API.

        Args:
            ioc_type: Type of IOC (domain, IP, or URL).
            value: IOC value.

        Returns:
            JSON response data or None on error.
        """
        try:
            # Map IOC type to URLhaus field
            field_map = {
                TIIndicatorType.DOMAIN: "host",
                TIIndicatorType.URL: "url",
                TIIndicatorType.IP: "host",
            }

            payload = {
                field_map[ioc_type]: value,
            }

            response = await self._client.post(
                "",
                data=payload,
            )

            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    # URLhaus sometimes returns plain text
                    pass

            return None

        except Exception as e:
            logger.error(f"abuse.ch request error: {e}")
            raise

    def _extract_threat_types(self, urls: list[dict]) -> list[str]:
        """Extract unique threat types from URL results.

        Args:
            urls: List of URL entries from URLhaus.

        Returns:
            List of unique threat types.
        """
        threat_types = set()
        for url in urls:
            threat_type = url.get("threat_type", "unknown")
            threat_types.add(threat_type)
        return list(threat_types)

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in URLhaus."""
        try:
            data = await self._query_urlhaus(TIIndicatorType.IP, ip)

            if not data or data.get("query_status") == "no_results":
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            if data.get("query_status") != "ok":
                return self._create_error_result(
                    ip, TIIndicatorType.IP, f"Query failed: {data.get('query_status')}"
                )

            urls = data.get("urls", [])
            threat_types = self._extract_threat_types(urls)

            # Get first/last seen from most recent URL
            first_seen = urls[0].get("firstseen") if urls else None
            last_seen = urls[0].get("lastseen") if urls else None

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(len(urls), threat_types),
                risk_score=float(len(urls) * 20),  # Scale based on URL count
                categories=threat_types,
                tags=[f"URLhaus: {t}" for t in threat_types],
                malicious_count=len(urls),
                total_count=len(urls),
                first_seen=first_seen,
                last_seen=last_seen,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain in URLhaus."""
        try:
            data = await self._query_urlhaus(TIIndicatorType.DOMAIN, domain)

            if not data or data.get("query_status") == "no_results":
                return TILookupResult(
                    source=self.source_name,
                    indicator=domain,
                    indicator_type=TIIndicatorType.DOMAIN,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            if data.get("query_status") != "ok":
                return self._create_error_result(
                    domain, TIIndicatorType.DOMAIN, f"Query failed: {data.get('query_status')}"
                )

            urls = data.get("urls", [])
            threat_types = self._extract_threat_types(urls)

            first_seen = urls[0].get("firstseen") if urls else None
            last_seen = urls[0].get("lastseen") if urls else None

            return TILookupResult(
                source=self.source_name,
                indicator=domain,
                indicator_type=TIIndicatorType.DOMAIN,
                success=True,
                risk_level=self._calculate_risk_level(len(urls), threat_types),
                risk_score=float(len(urls) * 20),
                categories=threat_types,
                tags=[f"URLhaus: {t}" for t in threat_types],
                malicious_count=len(urls),
                total_count=len(urls),
                first_seen=first_seen,
                last_seen=last_seen,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(domain, TIIndicatorType.DOMAIN, str(e))

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in URLhaus."""
        try:
            data = await self._query_urlhaus(TIIndicatorType.URL, url)

            if not data or data.get("query_status") == "no_results":
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            if data.get("query_status") != "ok":
                return self._create_error_result(
                    url, TIIndicatorType.URL, f"Query failed: {data.get('query_status')}"
                )

            urls = data.get("urls", [])
            threat_types = self._extract_threat_types(urls)

            first_seen = urls[0].get("firstseen") if urls else None
            last_seen = urls[0].get("lastseen") if urls else None

            return TILookupResult(
                source=self.source_name,
                indicator=url,
                indicator_type=TIIndicatorType.URL,
                success=True,
                risk_level=self._calculate_risk_level(len(urls), threat_types),
                risk_score=float(len(urls) * 20),
                categories=threat_types,
                tags=[f"URLhaus: {t}" for t in threat_types],
                malicious_count=len(urls),
                total_count=len(urls),
                first_seen=first_seen,
                last_seen=last_seen,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Hash lookups not supported by abuse.ch."""
        return self._create_not_supported_result(hash_value, hash_type)

    async def test_connection(self) -> bool:
        """Test the connection to abuse.ch.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            # Test with a status query
            response = await self._client.post(
                "",
                data={"query": "status"},
            )

            if response.status_code == 200:
                logger.info("abuse.ch connection test successful")
                return True
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except httpx.ConnectError:
            raise Exception("Could not connect to abuse.ch API - check network")
        except httpx.TimeoutException:
            raise Exception("Connection timed out")
        except Exception as e:
            if "API returned" in str(e) or "Could not connect" in str(e) or "Rate limit" in str(e):
                raise
            raise Exception(f"Connection failed: {e}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
