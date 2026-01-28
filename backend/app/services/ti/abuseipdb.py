"""AbuseIPDB Threat Intelligence client."""

import logging

import httpx

from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)

logger = logging.getLogger(__name__)

# AbuseIPDB API base URL
ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient(TIClient):
    """AbuseIPDB API client for IP reputation lookups."""

    source_name = "abuseipdb"
    supported_types = [TIIndicatorType.IP]

    def __init__(self, api_key: str, timeout: int = 30):
        """Initialize the AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=ABUSEIPDB_API_BASE,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def _calculate_risk_level(self, abuse_score: int) -> TIRiskLevel:
        """Calculate risk level based on AbuseIPDB confidence score.

        Args:
            abuse_score: Confidence score from 0-100.

        Returns:
            Risk level based on score.
        """
        if abuse_score >= 75:
            return TIRiskLevel.CRITICAL
        elif abuse_score >= 50:
            return TIRiskLevel.HIGH
        elif abuse_score >= 25:
            return TIRiskLevel.MEDIUM
        elif abuse_score > 0:
            return TIRiskLevel.LOW
        else:
            return TIRiskLevel.SAFE

    def _extract_categories(self, category_ids: list[int]) -> list[str]:
        """Convert AbuseIPDB category IDs to human-readable names.

        Args:
            category_ids: List of category IDs from AbuseIPDB.

        Returns:
            List of category names.
        """
        # AbuseIPDB category mapping
        category_map = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted",
        }

        return [category_map.get(cid, f"Category {cid}") for cid in category_ids]

    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address in AbuseIPDB."""
        try:
            response = await self._client.get(
                "/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,  # Look at last 90 days of reports
                    "verbose": True,
                },
            )
            response.raise_for_status()
            data = response.json()

            if "data" not in data:
                return self._create_error_result(
                    ip, TIIndicatorType.IP, "Invalid response from AbuseIPDB"
                )

            ip_data = data["data"]
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            total_reports = ip_data.get("totalReports", 0)

            # Extract unique categories from reports
            categories: list[int] = []
            reports = ip_data.get("reports", [])
            for report in reports:
                categories.extend(report.get("categories", []))
            unique_categories = list(set(categories))

            return TILookupResult(
                source=self.source_name,
                indicator=ip,
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=self._calculate_risk_level(abuse_score),
                risk_score=float(abuse_score),
                categories=self._extract_categories(unique_categories),
                malicious_count=total_reports,
                total_count=total_reports,
                country=ip_data.get("countryName"),
                country_code=ip_data.get("countryCode"),
                asn=str(ip_data.get("isp", "")) if ip_data.get("isp") else None,
                as_owner=ip_data.get("isp"),
                last_seen=ip_data.get("lastReportedAt"),
                raw_response=data,
            )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 422:
                # Invalid IP address
                return self._create_error_result(
                    ip, TIIndicatorType.IP, "Invalid IP address format"
                )
            return self._create_error_result(
                ip, TIIndicatorType.IP, f"API error: {e.response.status_code}"
            )
        except Exception as e:
            return self._create_error_result(ip, TIIndicatorType.IP, str(e))

    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Domain lookups not supported by AbuseIPDB."""
        return self._create_not_supported_result(domain, TIIndicatorType.DOMAIN)

    async def lookup_hash(
        self, hash_value: str, hash_type: TIIndicatorType
    ) -> TILookupResult:
        """Hash lookups not supported by AbuseIPDB."""
        return self._create_not_supported_result(hash_value, hash_type)

    async def lookup_url(self, url: str) -> TILookupResult:
        """URL lookups not supported by AbuseIPDB."""
        return self._create_not_supported_result(url, TIIndicatorType.URL)

    async def test_connection(self) -> bool:
        """Test the AbuseIPDB API connection."""
        try:
            # Test with a well-known safe IP (Google DNS)
            response = await self._client.get(
                "/check",
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
            )
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                raise Exception("Invalid API key - authentication failed")
            elif response.status_code == 402:
                raise Exception("API key quota exceeded")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except httpx.ConnectError:
            raise Exception("Could not connect to AbuseIPDB API - check network")
        except httpx.TimeoutException:
            raise Exception("Connection timed out")
        except Exception as e:
            if "Invalid API key" in str(e) or "API returned" in str(e) or "Could not connect" in str(e):
                raise
            raise Exception(f"Connection failed: {e}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
