"""ThreatFox (abuse.ch) Threat Intelligence client."""

import logging
from typing import Any

import httpx

from app.core.circuit_breaker import get_circuit_breaker
from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)

logger = logging.getLogger(__name__)

# ThreatFox API base URL
THREATFOX_API_BASE = "https://threatfox-api.abuse.ch/api/v1"


class ThreatFoxClient(TIClient):
    """ThreatFox API client for IOC lookups.

    ThreatFox is a free, community-driven platform by abuse.ch that shares
    Indicators of Compromise (IOCs) associated with malware.
    """

    source_name = "threatfox"
    supported_types = [
        TIIndicatorType.IP,
        TIIndicatorType.DOMAIN,
        TIIndicatorType.URL,
        TIIndicatorType.HASH_MD5,
        TIIndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        """Initialize the ThreatFox client.

        Args:
            api_key: Optional ThreatFox API key (free API doesn't require key).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        headers = {"Accept": "application/json"}
        if api_key:
            headers["API-KEY"] = api_key

        self._client = httpx.AsyncClient(
            base_url=THREATFOX_API_BASE,
            headers=headers,
            timeout=timeout,
        )

        # Initialize circuit breaker for ThreatFox API calls
        self._circuit_breaker = get_circuit_breaker(
            service_name="threatfox",
            failure_threshold=5,
            recovery_timeout=60.0,
            expected_exception=(httpx.HTTPError, httpx.TimeoutException, httpx.RequestError),
        )

    async def _search_ioc(self, search_term: str) -> dict[str, Any] | None:
        """Search for an IOC in ThreatFox (protected by circuit breaker).

        Args:
            search_term: The IOC to search for.

        Returns:
            Search results or None if not found.
        """
        # Define the actual API request logic
        async def _execute_search() -> dict[str, Any]:
            response = await self._client.post(
                "/",
                json={
                    "query": "search_ioc",
                    "search_term": search_term,
                },
            )
            response.raise_for_status()
            data = response.json()

            # ThreatFox returns query_status: "no_result" when not found
            if data.get("query_status") != "ok":
                # Return a special marker for "not found" (not an error)
                return {"_not_found": True}

            return data

        # Execute through circuit breaker
        try:
            result = await self._circuit_breaker.call(_execute_search)

            # Check if it's a "not found" result
            if isinstance(result, dict) and result.get("_not_found"):
                return None

            return result

        except Exception as e:
            logger.error(f"ThreatFox search error for '{search_term}': {e}")
            raise

    def _calculate_risk_level(self, confidence_level: int | None) -> TIRiskLevel:
        """Calculate risk level based on ThreatFox confidence.

        Args:
            confidence_level: Confidence level from 0-100.

        Returns:
            Risk level based on confidence.
        """
        # If found in ThreatFox, it's associated with malware
        if confidence_level is None:
            return TIRiskLevel.HIGH  # Default to high if found

        if confidence_level >= 75:
            return TIRiskLevel.CRITICAL
        elif confidence_level >= 50:
            return TIRiskLevel.HIGH
        elif confidence_level >= 25:
            return TIRiskLevel.MEDIUM
        else:
            return TIRiskLevel.LOW

    def _parse_ioc_result(
        self,
        indicator: str,
        indicator_type: TIIndicatorType,
        data: dict[str, Any],
    ) -> TILookupResult:
        """Parse ThreatFox IOC search results.

        Args:
            indicator: The original indicator searched.
            indicator_type: Type of indicator.
            data: ThreatFox API response.

        Returns:
            Parsed TILookupResult.
        """
        iocs = data.get("data", [])

        if not iocs:
            return TILookupResult(
                source=self.source_name,
                indicator=indicator,
                indicator_type=indicator_type,
                success=True,
                risk_level=TIRiskLevel.UNKNOWN,
            )

        # Use the first/most recent IOC entry
        ioc = iocs[0]

        # Extract malware family as category
        categories = []
        if ioc.get("malware"):
            categories.append(ioc["malware"])
        if ioc.get("malware_alias"):
            categories.append(ioc["malware_alias"])

        # Extract tags
        tags = ioc.get("tags", []) or []
        if ioc.get("threat_type"):
            tags.append(ioc["threat_type"])

        confidence = ioc.get("confidence_level")

        return TILookupResult(
            source=self.source_name,
            indicator=indicator,
            indicator_type=indicator_type,
            success=True,
            risk_level=self._calculate_risk_level(confidence),
            risk_score=float(confidence) if confidence else 75.0,
            categories=list(set(categories)),
            tags=list(set(tags)),
            malicious_count=len(iocs),
            total_count=len(iocs),
            first_seen=ioc.get("first_seen"),
            last_seen=ioc.get("last_seen"),
            raw_response=data,
        )

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in ThreatFox."""
        try:
            data = await self._search_ioc(ip)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            return self._parse_ioc_result(ip, TIIndicatorType.IP, data)

        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain in ThreatFox."""
        try:
            data = await self._search_ioc(domain)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=domain,
                    indicator_type=TIIndicatorType.DOMAIN,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            return self._parse_ioc_result(domain, TIIndicatorType.DOMAIN, data)

        except Exception as e:
            return self._create_error_result(domain, TIIndicatorType.DOMAIN, str(e))

    async def lookup_hash(
        self, hash_value: str, hash_type: TIIndicatorType
    ) -> TILookupResult:
        """Look up a file hash in ThreatFox."""
        # ThreatFox only supports MD5 and SHA256
        if hash_type == TIIndicatorType.HASH_SHA1:
            return self._create_not_supported_result(hash_value, hash_type)

        try:
            data = await self._search_ioc(hash_value)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=hash_value,
                    indicator_type=hash_type,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            return self._parse_ioc_result(hash_value, hash_type, data)

        except Exception as e:
            return self._create_error_result(hash_value, hash_type, str(e))

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in ThreatFox."""
        try:
            data = await self._search_ioc(url)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            return self._parse_ioc_result(url, TIIndicatorType.URL, data)

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def test_connection(self) -> bool:
        """Test the ThreatFox API connection."""
        try:
            # Use a simple query to test connectivity
            response = await self._client.post(
                "/",
                json={"query": "get_ioc_types"},
            )
            if response.status_code == 200:
                return True
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except httpx.ConnectError:
            raise Exception("Could not connect to ThreatFox API - check network")
        except httpx.TimeoutException:
            raise Exception("Connection timed out")
        except Exception as e:
            if "API returned" in str(e) or "Could not connect" in str(e) or "Rate limit" in str(e):
                raise
            raise Exception(f"Connection failed: {e}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
