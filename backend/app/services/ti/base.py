"""Base Threat Intelligence client interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TIIndicatorType(str, Enum):
    """Types of indicators that can be looked up."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class TIRiskLevel(str, Enum):
    """Risk levels returned by TI sources."""

    UNKNOWN = "unknown"
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TILookupResult:
    """Result from a TI lookup."""

    # Source information
    source: str  # e.g., "virustotal", "abuseipdb"
    indicator: str  # The value that was looked up
    indicator_type: TIIndicatorType

    # Whether the lookup was successful
    success: bool = True
    error: str | None = None

    # Risk assessment
    risk_level: TIRiskLevel = TIRiskLevel.UNKNOWN
    risk_score: float | None = None  # Normalized 0-100 score

    # Categorization
    categories: list[str] = field(default_factory=list)  # e.g., ["malware", "phishing"]
    tags: list[str] = field(default_factory=list)

    # Detection statistics
    malicious_count: int = 0
    total_count: int = 0

    # Geographic information (for IPs)
    country: str | None = None
    country_code: str | None = None
    asn: str | None = None
    as_owner: str | None = None

    # Timestamps
    first_seen: str | None = None
    last_seen: str | None = None

    # Raw response for additional data
    raw_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "success": self.success,
            "error": self.error,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "tags": self.tags,
            "malicious_count": self.malicious_count,
            "total_count": self.total_count,
            "country": self.country,
            "country_code": self.country_code,
            "asn": self.asn,
            "as_owner": self.as_owner,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class TIClient(ABC):
    """Abstract base class for Threat Intelligence clients."""

    # Source identifier (e.g., "virustotal", "abuseipdb")
    source_name: str = "unknown"

    # What indicator types this source supports
    supported_types: list[TIIndicatorType] = []

    @abstractmethod
    async def lookup_ip(self, ip: str) -> TILookupResult:
        """Look up an IP address.

        Args:
            ip: The IP address to look up.

        Returns:
            TILookupResult with findings or error.
        """
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> TILookupResult:
        """Look up a domain.

        Args:
            domain: The domain to look up.

        Returns:
            TILookupResult with findings or error.
        """
        pass

    @abstractmethod
    async def lookup_hash(self, hash_value: str, hash_type: TIIndicatorType) -> TILookupResult:
        """Look up a file hash.

        Args:
            hash_value: The hash value to look up.
            hash_type: The type of hash (MD5, SHA1, SHA256).

        Returns:
            TILookupResult with findings or error.
        """
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> TILookupResult:
        """Look up a URL.

        Args:
            url: The URL to look up.

        Returns:
            TILookupResult with findings or error.
        """
        pass

    async def lookup(self, indicator: str, indicator_type: TIIndicatorType) -> TILookupResult:
        """Generic lookup dispatcher.

        Args:
            indicator: The value to look up.
            indicator_type: The type of indicator.

        Returns:
            TILookupResult with findings or error.
        """
        if indicator_type not in self.supported_types:
            return TILookupResult(
                source=self.source_name,
                indicator=indicator,
                indicator_type=indicator_type,
                success=False,
                error=f"Indicator type {indicator_type.value} not supported by {self.source_name}",
            )

        match indicator_type:
            case TIIndicatorType.IP:
                return await self.lookup_ip(indicator)
            case TIIndicatorType.DOMAIN:
                return await self.lookup_domain(indicator)
            case TIIndicatorType.URL:
                return await self.lookup_url(indicator)
            case TIIndicatorType.HASH_MD5 | TIIndicatorType.HASH_SHA1 | TIIndicatorType.HASH_SHA256:
                return await self.lookup_hash(indicator, indicator_type)
            case _:
                return TILookupResult(
                    source=self.source_name,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    success=False,
                    error=f"Unknown indicator type: {indicator_type}",
                )

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test the connection to the TI source.

        Returns:
            True if connection is successful, False otherwise.
        """
        pass

    def _create_error_result(
        self,
        indicator: str,
        indicator_type: TIIndicatorType,
        error: str,
    ) -> TILookupResult:
        """Create an error result."""
        return TILookupResult(
            source=self.source_name,
            indicator=indicator,
            indicator_type=indicator_type,
            success=False,
            error=error,
        )

    def _create_not_supported_result(
        self,
        indicator: str,
        indicator_type: TIIndicatorType,
    ) -> TILookupResult:
        """Create a result for unsupported indicator types."""
        return TILookupResult(
            source=self.source_name,
            indicator=indicator,
            indicator_type=indicator_type,
            success=False,
            error=f"{indicator_type.value} lookups not supported by {self.source_name}",
        )
