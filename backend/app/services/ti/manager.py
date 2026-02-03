"""Threat Intelligence enrichment manager."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt
from app.models.ti_config import TISourceConfig, TISourceType
from app.services.system_log import LogCategory, system_log_service
from app.services.ti.abuse_ch import AbuseCHClient
from app.services.ti.abuseipdb import AbuseIPDBClient
from app.services.ti.alienvault_otx import AlienVaultOTXClient
from app.services.ti.base import (
    TIClient,
    TIIndicatorType,
    TILookupResult,
    TIRiskLevel,
)
from app.services.ti.greynoise import GreyNoiseClient
from app.services.ti.misp import MISPClient
from app.services.ti.phishtank import PhishTankClient
from app.services.ti.threatfox import ThreatFoxClient
from app.services.ti.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)

# Default timeout for individual source lookups
DEFAULT_LOOKUP_TIMEOUT = 10  # seconds


@dataclass
class TIEnrichmentResult:
    """Combined result from multiple TI sources."""

    indicator: str
    indicator_type: TIIndicatorType

    # Aggregated risk assessment
    overall_risk_level: TIRiskLevel = TIRiskLevel.UNKNOWN
    overall_risk_score: float = 0.0
    highest_risk_source: str | None = None

    # Results from individual sources
    source_results: list[TILookupResult] = field(default_factory=list)

    # Summary statistics
    sources_queried: int = 0
    sources_with_results: int = 0
    sources_with_detections: int = 0

    # Combined categories and tags from all sources
    all_categories: list[str] = field(default_factory=list)
    all_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "overall_risk_level": self.overall_risk_level.value,
            "overall_risk_score": self.overall_risk_score,
            "highest_risk_source": self.highest_risk_source,
            "sources_queried": self.sources_queried,
            "sources_with_results": self.sources_with_results,
            "sources_with_detections": self.sources_with_detections,
            "all_categories": self.all_categories,
            "all_tags": self.all_tags,
            "source_results": [r.to_dict() for r in self.source_results],
        }


class TIEnrichmentManager:
    """Orchestrates TI lookups across multiple sources."""

    def __init__(self, lookup_timeout: int = DEFAULT_LOOKUP_TIMEOUT):
        """Initialize the enrichment manager.

        Args:
            lookup_timeout: Timeout for individual source lookups.
        """
        self.lookup_timeout = lookup_timeout
        self._clients: dict[str, TIClient] = {}

    async def initialize(self, db: AsyncSession) -> None:
        """Initialize TI clients from database configuration.

        Args:
            db: Database session for loading configurations.
        """
        result = await db.execute(
            select(TISourceConfig).where(TISourceConfig.is_enabled.is_(True))
        )
        configs = result.scalars().all()

        for config in configs:
            try:
                client = self._create_client(config)
                if client:
                    self._clients[config.source_type] = client
                    logger.info("Initialized TI client: %s", config.source_type)
            except Exception as e:
                logger.error("Failed to initialize TI client %s: %s", config.source_type, e)
                await system_log_service.log_error(
                    db,
                    category=LogCategory.INTEGRATIONS,
                    service="ti_manager",
                    message=f"TI feed sync failed: {str(e)}",
                    details={"error": str(e), "error_type": type(e).__name__, "source_type": config.source_type}
                )

    def _create_client(self, config: TISourceConfig) -> TIClient | None:
        """Create a TI client from configuration.

        Args:
            config: Source configuration from database.

        Returns:
            Initialized TI client or None.
        """
        api_key = None
        if config.api_key_encrypted:
            api_key = decrypt(config.api_key_encrypted)

        source_type = config.source_type
        instance_url = config.instance_url

        match source_type:
            case TISourceType.VIRUSTOTAL.value:
                if not api_key:
                    logger.warning("VirusTotal requires an API key")
                    return None
                return VirusTotalClient(api_key)

            case TISourceType.ABUSEIPDB.value:
                if not api_key:
                    logger.warning("AbuseIPDB requires an API key")
                    return None
                return AbuseIPDBClient(api_key)

            case TISourceType.GREYNOISE.value:
                if not api_key:
                    logger.warning("GreyNoise requires an API key")
                    return None
                return GreyNoiseClient(api_key)

            case TISourceType.THREATFOX.value:
                # ThreatFox doesn't require an API key
                return ThreatFoxClient(api_key)

            case TISourceType.MISP.value:
                if not api_key:
                    logger.warning("MISP requires an API key")
                    return None
                if not instance_url:
                    logger.warning("MISP requires an instance URL")
                    return None
                return MISPClient(api_key, instance_url)

            case TISourceType.ABUSE_CH.value:
                # abuse.ch (URLhaus) doesn't require an API key
                return AbuseCHClient(api_key)

            case TISourceType.ALIENVAULT_OTX.value:
                if not api_key:
                    logger.warning("AlienVault OTX requires an API key")
                    return None
                return AlienVaultOTXClient(api_key)

            case TISourceType.PHISHTANK.value:
                # PhishTank doesn't require an API key
                return PhishTankClient(api_key)

            case _:
                logger.warning("Unknown TI source type: %s", source_type)
                return None

    async def _lookup_with_timeout(
        self,
        client: TIClient,
        indicator: str,
        indicator_type: TIIndicatorType,
    ) -> TILookupResult:
        """Perform a lookup with timeout handling.

        Args:
            client: TI client to use.
            indicator: Value to look up.
            indicator_type: Type of indicator.

        Returns:
            Lookup result or error result on timeout.
        """
        try:
            result = await asyncio.wait_for(
                client.lookup(indicator, indicator_type),
                timeout=self.lookup_timeout,
            )
            return result
        except TimeoutError:
            return TILookupResult(
                source=client.source_name,
                indicator=indicator,
                indicator_type=indicator_type,
                success=False,
                error="Lookup timed out",
            )
        except Exception as e:
            return TILookupResult(
                source=client.source_name,
                indicator=indicator,
                indicator_type=indicator_type,
                success=False,
                error=str(e),
            )

    def _aggregate_results(
        self,
        indicator: str,
        indicator_type: TIIndicatorType,
        results: list[TILookupResult],
    ) -> TIEnrichmentResult:
        """Aggregate results from multiple sources.

        Args:
            indicator: The looked up indicator.
            indicator_type: Type of indicator.
            results: Results from individual sources.

        Returns:
            Aggregated enrichment result.
        """
        enrichment = TIEnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            source_results=results,
            sources_queried=len(results),
        )

        # Track highest risk
        highest_risk_score = 0.0
        highest_risk_level = TIRiskLevel.UNKNOWN
        highest_risk_source = None

        # Aggregate from all results
        all_categories = set()
        all_tags = set()

        for result in results:
            if not result.success:
                continue

            enrichment.sources_with_results += 1

            if result.malicious_count > 0:
                enrichment.sources_with_detections += 1

            # Track highest risk
            score = result.risk_score or 0.0
            if score > highest_risk_score:
                highest_risk_score = score
                highest_risk_source = result.source

            # Compare risk levels
            risk_order = [
                TIRiskLevel.UNKNOWN,
                TIRiskLevel.SAFE,
                TIRiskLevel.LOW,
                TIRiskLevel.MEDIUM,
                TIRiskLevel.HIGH,
                TIRiskLevel.CRITICAL,
            ]
            if risk_order.index(result.risk_level) > risk_order.index(highest_risk_level):
                highest_risk_level = result.risk_level

            # Collect categories and tags
            all_categories.update(result.categories)
            all_tags.update(result.tags)

        enrichment.overall_risk_score = highest_risk_score
        enrichment.overall_risk_level = highest_risk_level
        enrichment.highest_risk_source = highest_risk_source
        enrichment.all_categories = list(all_categories)
        enrichment.all_tags = list(all_tags)

        return enrichment

    async def enrich(
        self,
        indicator: str,
        indicator_type: TIIndicatorType,
    ) -> TIEnrichmentResult:
        """Enrich an indicator using all enabled TI sources.

        Args:
            indicator: Value to look up.
            indicator_type: Type of indicator.

        Returns:
            Aggregated enrichment result from all sources.
        """
        if not self._clients:
            return TIEnrichmentResult(
                indicator=indicator,
                indicator_type=indicator_type,
            )

        # Get clients that support this indicator type
        applicable_clients = [
            client
            for client in self._clients.values()
            if indicator_type in client.supported_types
        ]

        if not applicable_clients:
            return TIEnrichmentResult(
                indicator=indicator,
                indicator_type=indicator_type,
            )

        # Run all lookups in parallel
        tasks = [
            self._lookup_with_timeout(client, indicator, indicator_type)
            for client in applicable_clients
        ]

        results = await asyncio.gather(*tasks)

        return self._aggregate_results(indicator, indicator_type, list(results))

    async def enrich_ip(self, ip: str) -> TIEnrichmentResult:
        """Convenience method to enrich an IP address."""
        return await self.enrich(ip, TIIndicatorType.IP)

    async def enrich_domain(self, domain: str) -> TIEnrichmentResult:
        """Convenience method to enrich a domain."""
        return await self.enrich(domain, TIIndicatorType.DOMAIN)

    async def enrich_url(self, url: str) -> TIEnrichmentResult:
        """Convenience method to enrich a URL."""
        return await self.enrich(url, TIIndicatorType.URL)

    async def enrich_hash(
        self, hash_value: str, hash_type: TIIndicatorType
    ) -> TIEnrichmentResult:
        """Convenience method to enrich a file hash."""
        return await self.enrich(hash_value, hash_type)

    async def close(self) -> None:
        """Close all TI clients."""
        for client in self._clients.values():
            if hasattr(client, "close"):
                await client.close()
        self._clients.clear()

    @property
    def enabled_sources(self) -> list[str]:
        """Get list of enabled source names."""
        return list(self._clients.keys())
