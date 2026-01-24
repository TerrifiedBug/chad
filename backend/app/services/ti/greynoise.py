"""GreyNoise Threat Intelligence client."""

import logging

import httpx

from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)

logger = logging.getLogger(__name__)

# GreyNoise API base URL
GREYNOISE_API_BASE = "https://api.greynoise.io/v3"


class GreyNoiseClient(TIClient):
    """GreyNoise API client for IP intelligence lookups.

    GreyNoise categorizes IPs into:
    - Benign: Known good actors (crawlers, VPNs, etc.)
    - Malicious: Known bad actors actively attacking
    - Unknown: Not seen in GreyNoise data
    """

    source_name = "greynoise"
    supported_types = [TIIndicatorType.IP]

    def __init__(self, api_key: str, timeout: int = 30):
        """Initialize the GreyNoise client.

        Args:
            api_key: GreyNoise API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=GREYNOISE_API_BASE,
            headers={
                "key": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _calculate_risk_level(
        self, classification: str, is_riot: bool, is_noise: bool
    ) -> TIRiskLevel:
        """Calculate risk level based on GreyNoise classification.

        Args:
            classification: GreyNoise classification (benign, malicious, unknown).
            is_riot: Whether IP is in RIOT dataset (trusted business services).
            is_noise: Whether IP is seen scanning the internet.

        Returns:
            Risk level based on classification.
        """
        if is_riot:
            return TIRiskLevel.SAFE

        match classification:
            case "malicious":
                return TIRiskLevel.HIGH
            case "benign":
                return TIRiskLevel.SAFE
            case _:
                # Unknown - if it's noise, slightly elevated
                if is_noise:
                    return TIRiskLevel.LOW
                return TIRiskLevel.UNKNOWN

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in GreyNoise.

        Uses the Community API endpoint for basic lookups.
        """
        try:
            # Use context endpoint for full context
            response = await self._client.get(f"/community/{ip}")

            if response.status_code == 404:
                # IP not found in GreyNoise
                return TILookupResult(
                    source=self.source_name,
                    indicator=ip,
                    indicator_type=TIIndicatorType.IP,
                    success=True,
                    risk_level=TIRiskLevel.UNKNOWN,
                )

            response.raise_for_status()
            data = response.json()

            classification = data.get("classification", "unknown")
            is_noise = data.get("noise", False)
            is_riot = data.get("riot", False)

            # Build categories from classification and context
            categories = []
            if classification:
                categories.append(classification)
            if is_noise:
                categories.append("internet_scanner")
            if is_riot:
                categories.append("trusted_service")

            # Build tags from various fields
            tags = []
            if data.get("name"):
                tags.append(data["name"])
            if data.get("link"):
                tags.append("documented")

            # Calculate risk score
            risk_score = 0.0
            if classification == "malicious":
                risk_score = 75.0
            elif classification == "benign" or is_riot:
                risk_score = 0.0
            elif is_noise:
                risk_score = 25.0

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(classification, is_riot, is_noise),
                risk_score=risk_score,
                categories=categories,
                tags=tags,
                # GreyNoise doesn't provide detection counts in community API
                malicious_count=1 if classification == "malicious" else 0,
                total_count=1,
                last_seen=data.get("last_seen"),
                raw_response=data,
            )

        except httpx.HTTPStatusError as e:
            return self._create_error_result(
                ip, TIIndicatorType.IP, f"API error: {e.response.status_code}"
            )
        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Domain lookups not supported by GreyNoise."""
        return self._create_not_supported_result(domain, TIIndicatorType.DOMAIN)

    async def lookup_hash(
        self, hash_value: str, hash_type: TIIndicatorType
    ) -> TILookupResult:
        """Hash lookups not supported by GreyNoise."""
        return self._create_not_supported_result(hash_value, hash_type)

    async def lookup_url(self, url: str) -> TILookupResult:
        """URL lookups not supported by GreyNoise."""
        return self._create_not_supported_result(url, TIIndicatorType.URL)

    async def test_connection(self) -> bool:
        """Test the GreyNoise API connection."""
        try:
            # Test with a well-known IP that's likely in GreyNoise
            response = await self._client.get("/community/8.8.8.8")
            return response.status_code in (200, 404)  # 404 is valid for unknown IPs
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
