"""MISP Threat Intelligence client."""

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


class MISPClient(TIClient):
    """MISP API client for threat intelligence lookups.

    MISP (Malware Information Sharing Platform) is a threat sharing platform
    for storing, sharing and collaborating on IOC data and malware analysis.
    """

    source_name = "misp"
    supported_types = [
        TIIndicatorType.DOMAIN,
        TIIndicatorType.IP,
        TIIndicatorType.URL,
        TIIndicatorType.HASH_MD5,
        TIIndicatorType.HASH_SHA1,
        TIIndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str, instance_url: str, timeout: int = 30):
        """Initialize the MISP client.

        Args:
            api_key: MISP API key.
            instance_url: Base URL of MISP instance (e.g., https://misp.example.com).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.instance_url = instance_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.instance_url,
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _map_indicator_type(self, indicator_type: TIIndicatorType) -> str:
        """Map TI indicator types to MISP attribute types.

        Args:
            indicator_type: Our indicator type enum.

        Returns:
            MISP attribute type string.
        """
        mapping = {
            TIIndicatorType.DOMAIN: "domain",
            TIIndicatorType.IP: "ip-dst",
            TIIndicatorType.URL: "url",
            TIIndicatorType.HASH_MD5: "md5",
            TIIndicatorType.HASH_SHA1: "sha1",
            TIIndicatorType.HASH_SHA256: "sha256",
        }
        return mapping.get(indicator_type, "text")

    def _calculate_risk_level(self, distribution_level: int, event_count: int) -> TIRiskLevel:
        """Calculate risk level based on MISP distribution and event count.

        Args:
            distribution_level: MISP distribution level (0-5).
            event_count: Number of events associated with this IOC.

        Returns:
            Risk level assessment.
        """
        # Higher distribution = more widely shared = higher confidence
        # More events = more sightings = higher risk
        if distribution_level >= 3 or event_count >= 5:
            return TIRiskLevel.HIGH
        elif distribution_level >= 2 or event_count >= 2:
            return TIRiskLevel.MEDIUM
        elif event_count >= 1:
            return TIRiskLevel.LOW
        else:
            return TIRiskLevel.UNKNOWN

    async def _search_attributes(self, value: str, attribute_type: str) -> dict[str, Any] | None:
        """Search for attributes in MISP.

        Args:
            value: The IOC value to search for.
            attribute_type: MISP attribute type.

        Returns:
            JSON response data or None on error.
        """
        try:
            response = await self._client.post(
                "/attributes/restSearch",
                json={
                    "value": value,
                    "type": attribute_type,
                    "enforceWarninglist": True,
                },
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"MISP API error: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"MISP request error: {e}")
            raise

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in MISP."""
        try:
            misp_type = self._map_indicator_type(TIIndicatorType.IP)
            data = await self._search_attributes(ip, misp_type)

            if not data or "Attribute" not in data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            attributes = data["Attribute"]

            # Get unique event IDs and max distribution level
            event_ids = set()
            max_distribution = 0
            categories = set()

            for attr in attributes:
                event_ids.add(attr.get("event_id"))
                max_distribution = max(max_distribution, attr.get("distribution", 0))
                if attr.get("category"):
                    categories.add(attr["category"])

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(max_distribution, len(event_ids)),
                risk_score=float(max_distribution * 20),  # 0-100 based on distribution
                categories=list(categories),
                malicious_count=len(event_ids),
                total_count=len(event_ids),
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain in MISP."""
        try:
            misp_type = self._map_indicator_type(TIIndicatorType.DOMAIN)
            data = await self._search_attributes(domain, misp_type)

            if not data or "Attribute" not in data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=domain,
                    indicator_type=TIIndicatorType.DOMAIN,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            attributes = data["Attribute"]

            # Get unique event IDs and max distribution level
            event_ids = set()
            max_distribution = 0
            categories = set()
            tags = set()

            for attr in attributes:
                event_ids.add(attr.get("event_id"))
                max_distribution = max(max_distribution, attr.get("distribution", 0))
                if attr.get("category"):
                    categories.add(attr["category"])
                if attr.get("Tag"):
                    for tag in attr.get("Tag", []):
                        tags.add(tag.get("name", ""))

            return TILookupResult(
                source=self.source_name,
                indicator=domain,
                indicator_type=TIIndicatorType.DOMAIN,
                success=True,
                risk_level=self._calculate_risk_level(max_distribution, len(event_ids)),
                risk_score=float(max_distribution * 20),
                categories=list(categories),
                tags=list(tags),
                malicious_count=len(event_ids),
                total_count=len(event_ids),
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(domain, TIIndicatorType.DOMAIN, str(e))

    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL in MISP."""
        try:
            misp_type = self._map_indicator_type(TIIndicatorType.URL)
            data = await self._search_attributes(url, misp_type)

            if not data or "Attribute" not in data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=url,
                    indicator_type=TIIndicatorType.URL,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            attributes = data["Attribute"]

            event_ids = set()
            max_distribution = 0
            categories = set()

            for attr in attributes:
                event_ids.add(attr.get("event_id"))
                max_distribution = max(max_distribution, attr.get("distribution", 0))
                if attr.get("category"):
                    categories.add(attr["category"])

            return TILookupResult(
                source=self.source_name,
                indicator=url,
                indicator_type=TIIndicatorType.URL,
                success=True,
                risk_level=self._calculate_risk_level(max_distribution, len(event_ids)),
                risk_score=float(max_distribution * 20),
                categories=list(categories),
                malicious_count=len(event_ids),
                total_count=len(event_ids),
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(url, TIIndicatorType.URL, str(e))

    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Look up a file hash in MISP."""
        try:
            misp_type = self._map_indicator_type(hash_type)
            data = await self._search_attributes(hash_value, misp_type)

            if not data or "Attribute" not in data:
                return TILookupResult(
                    source=self.source_name,
                    indicator=hash_value,
                    indicator_type=hash_type,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                    raw_response=data or {},
                )

            attributes = data["Attribute"]

            event_ids = set()
            max_distribution = 0
            categories = set()
            tags = set()

            for attr in attributes:
                event_ids.add(attr.get("event_id"))
                max_distribution = max(max_distribution, attr.get("distribution", 0))
                if attr.get("category"):
                    categories.add(attr["category"])
                if attr.get("Tag"):
                    for tag in attr.get("Tag", []):
                        tags.add(tag.get("name", ""))

            return TILookupResult(
                source=self.source_name,
                indicator=hash_value,
                indicator_type=hash_type,
                success=True,
                risk_level=self._calculate_risk_level(max_distribution, len(event_ids)),
                risk_score=float(max_distribution * 20),
                categories=list(categories),
                tags=list(tags),
                malicious_count=len(event_ids),
                total_count=len(event_ids),
                raw_response=data,
            )

        except Exception as e:
            return self._create_error_result(hash_value, hash_type, str(e))

    async def test_connection(self) -> bool:
        """Test the connection to MISP.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            # Try to get a single event to test authentication
            response = await self._client.get(
                "/events/index",
                params={"limit": 1},
            )
            response.raise_for_status()
            logger.info("MISP connection test successful")
            return True

        except Exception as e:
            logger.error(f"MISP connection test failed: {e}")
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
