"""AlienVault OTX Threat Intelligence client.

AlienVault OTX (Open Threat Exchange) is a threat intelligence platform
that allows security researchers and data lovers to share threat data.
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

# AlienVault OTX API base URL
OTX_API_BASE = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXClient(TIClient):
    """AlienVault OTX API client for threat intelligence lookups.

    OTX provides a massive collection of threat data from the AlienVault
    Labs research team, the Open Threat Exchange community, and other
    external sources.
    """

    source_name = "alienvault_otx"
    supported_types = [
        TIIndicatorType.DOMAIN,
        TIIndicatorType.IP,
        TIIndicatorType.URL,
        TIIndicatorType.HASH_MD5,
        TIIndicatorType.HASH_SHA1,
        TIIndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str, timeout: int = 30):
        """Initialize the AlienVault OTX client.

        Args:
            api_key: AlienVault OTX API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=OTX_API_BASE,
            headers={
                "X-OTX-API-KEY": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _calculate_risk_level(self, pulse_count: int) -> TIRiskLevel:
        """Calculate risk level based on pulse count.

        Args:
            pulse_count: Number of pulses associated with this IOC.

        Returns:
            Risk level assessment.
        """
        if pulse_count >= 10:
            return TIRiskLevel.CRITICAL
        elif pulse_count >= 5:
            return TIRiskLevel.HIGH
        elif pulse_count >= 2:
            return TIRiskLevel.MEDIUM
        elif pulse_count == 1:
            return TIRiskLevel.LOW
        else:
            return TIRiskLevel.UNKNOWN

    async def _get_indicator_section(self, section: str, indicator: str) -> dict[str, Any] | None:
        """Get a specific section of an indicator report.

        Args:
            section: Section name (general, reputation, etc).
            indicator: The indicator value.

        Returns:
            JSON response data or None on error.
        """
        try:
            response = await self._client.get(
                f"/indicators/{section}/{indicator}",
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"AlienVault OTX API error: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"AlienVault OTX request error: {e}")
            raise

    def _extract_pulse_info(self, data: dict[str, Any]) -> tuple[int, list[str], list[str]]:
        """Extract pulse information from OTX response.

        Args:
            data: OTX API response data.

        Returns:
            Tuple of (pulse_count, tags, pulse_names).
        """
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        pulse_count = len(pulses)
        tags = set()
        pulse_names = []

        for pulse in pulses:
            pulse_names.append(pulse.get("name", ""))
            for tag in pulse.get("tags", []):
                tags.add(tag)

        return pulse_count, list(tags), pulse_names

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in AlienVault OTX."""
        try:
            data = await self._get_indicator_section("IPv4", ip)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response={},
                )

            pulse_count, tags, _ = self._extract_pulse_info(data)
            reputation = data.get("reputation", {})

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(pulse_count),
                risk_score=float(min(pulse_count * 10, 100)),
                categories=tags,
                tags=tags,
                malicious_count=pulse_count,
                total_count=pulse_count,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain in AlienVault OTX."""
        try:
            data = await self._get_indicator_section("domain", domain)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=domain,
                    indicator_type=TIIndicatorType.DOMAIN,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response={},
                )

            pulse_count, tags, _ = self._extract_pulse_info(data)
            whois = data.get("whois", "")

            return TILookupResult(
                source=self.source_name,
                indicator=domain,
                indicator_type=TIIndicatorType.DOMAIN,
                success=True,
                risk_level=self._calculate_risk_level(pulse_count),
                risk_score=float(min(pulse_count * 10, 100)),
                categories=tags,
                tags=tags,
                malicious_count=pulse_count,
                total_count=pulse_count,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(domain, TIIndicatorType.DOMAIN, str(e))

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in AlienVault OTX."""
        try:
            # URL needs to be encoded in the request
            data = await self._get_indicator_section("url", url)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response={},
                )

            pulse_count, tags, _ = self._extract_pulse_info(data)

            return TILookupResult(
                source=self.source_name,
                indicator=url,
                indicator_type=TIIndicatorType.URL,
                success=True,
                risk_level=self._calculate_risk_level(pulse_count),
                risk_score=float(min(pulse_count * 10, 100)),
                categories=tags,
                tags=tags,
                malicious_count=pulse_count,
                total_count=pulse_count,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Look up a file hash in AlienVault OTX."""
        try:
            data = await self._get_indicator_section("file", hash_value)

            if not data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=hash_value,
                    indicator_type=hash_type,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response={},
                )

            pulse_count, tags, _ = self._extract_pulse_info(data)

            # Extract malware analysis if available
            analysis = data.get("analysis", {})
            detections = []
            if analysis:
                for engine, result in analysis.get("results", {}).items():
                    if result.get("malware"):
                        detections.append(engine)

            return TILookupResult(
                source=self.source_name,
                indicator=hash_value,
                indicator_type=hash_type,
                success=True,
                risk_level=self._calculate_risk_level(pulse_count),
                risk_score=float(min(pulse_count * 10, 100)),
                categories=tags,
                tags=tags,
                malicious_count=pulse_count,
                total_count=pulse_count,
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(hash_value, hash_type, str(e))

    async def test_connection(self) -> bool:
        """Test the connection to AlienVault OTX.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            # Get user info to test authentication
            response = await self._client.get("/users/me")
            response.raise_for_status()
            logger.info("AlienVault OTX connection test successful")
            return True

        except Exception as e:
            logger.error(f"AlienVault OTX connection test failed: {e}")
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
