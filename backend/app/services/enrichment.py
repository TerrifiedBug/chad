"""
Alert enrichment service.

Enriches alert data with additional context like GeoIP and Threat Intelligence.
"""
import ipaddress
import logging
import re
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern
from app.services.geoip import geoip_service
from app.services.settings import get_setting
from app.services.ti import TIEnrichmentManager, TIIndicatorType

logger = logging.getLogger(__name__)

# Regex patterns for indicator extraction
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def get_nested_value(doc: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation."""
    keys = path.split(".")
    value = doc
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def set_nested_value(doc: dict, path: str, value: Any):
    """Set a value in a nested dict using dot notation."""
    keys = path.split(".")
    current = doc
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public (not private/reserved)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False


def extract_indicators(doc: dict, max_per_type: int = 5) -> dict[TIIndicatorType, list[str]]:
    """
    Extract potential threat indicators from a log document.

    Args:
        doc: The log document to extract indicators from.
        max_per_type: Maximum indicators to return per type.

    Returns:
        Dictionary mapping indicator types to lists of unique values.
    """
    # Convert doc to JSON string for pattern matching
    doc_str = str(doc)

    indicators: dict[TIIndicatorType, set[str]] = {
        TIIndicatorType.IP: set(),
        TIIndicatorType.DOMAIN: set(),
        TIIndicatorType.HASH_MD5: set(),
        TIIndicatorType.HASH_SHA1: set(),
        TIIndicatorType.HASH_SHA256: set(),
    }

    # Extract IPs (only public ones)
    for match in IP_PATTERN.findall(doc_str):
        if is_public_ip(match):
            indicators[TIIndicatorType.IP].add(match)

    # Extract domains (exclude common false positives)
    excluded_domains = {
        "localhost",
        "example.com",
        "test.com",
        "local",
    }
    for match in DOMAIN_PATTERN.findall(doc_str):
        match_lower = match.lower()
        # Skip if it looks like a version number or common pattern
        if not any(
            match_lower.endswith(exc) or match_lower == exc
            for exc in excluded_domains
        ):
            indicators[TIIndicatorType.DOMAIN].add(match_lower)

    # Extract hashes (prioritize SHA256 > SHA1 > MD5)
    for match in SHA256_PATTERN.findall(doc_str):
        indicators[TIIndicatorType.HASH_SHA256].add(match.lower())
    for match in SHA1_PATTERN.findall(doc_str):
        # Skip if it's part of a SHA256 hash
        if match.lower() not in str(indicators[TIIndicatorType.HASH_SHA256]):
            indicators[TIIndicatorType.HASH_SHA1].add(match.lower())
    for match in MD5_PATTERN.findall(doc_str):
        # Skip if it's part of a longer hash
        if (
            match.lower() not in str(indicators[TIIndicatorType.HASH_SHA256])
            and match.lower() not in str(indicators[TIIndicatorType.HASH_SHA1])
        ):
            indicators[TIIndicatorType.HASH_MD5].add(match.lower())

    # Limit results per type
    return {
        indicator_type: list(values)[:max_per_type]
        for indicator_type, values in indicators.items()
        if values
    }


# Global TI manager instance (initialized on first use)
_ti_manager: TIEnrichmentManager | None = None


async def get_ti_manager(db: AsyncSession) -> TIEnrichmentManager:
    """Get or create the TI enrichment manager."""
    global _ti_manager
    if _ti_manager is None:
        _ti_manager = TIEnrichmentManager()
        await _ti_manager.initialize(db)
    return _ti_manager


async def reinitialize_ti_manager(db: AsyncSession) -> None:
    """Reinitialize the TI manager (call after config changes)."""
    global _ti_manager
    if _ti_manager:
        await _ti_manager.close()
    _ti_manager = TIEnrichmentManager()
    await _ti_manager.initialize(db)


async def enrich_alert(
    db: AsyncSession,
    log_doc: dict,
    index_pattern: IndexPattern,
) -> dict:
    """
    Enrich a log document with additional context.

    Args:
        db: Database session
        log_doc: The matched log document
        index_pattern: The index pattern configuration

    Returns:
        Enriched log document (copy, original not modified)
    """
    # Make a copy to avoid modifying original
    enriched = dict(log_doc)

    # GeoIP enrichment
    await _enrich_geoip(db, enriched, log_doc, index_pattern)

    # Threat Intelligence enrichment
    await _enrich_ti(db, enriched, log_doc)

    return enriched


async def _enrich_geoip(
    db: AsyncSession,
    enriched: dict,
    log_doc: dict,
    index_pattern: IndexPattern,
) -> None:
    """Add GeoIP enrichment to the document."""
    # Check if GeoIP is enabled
    geoip_settings = await get_setting(db, "geoip")
    geoip_enabled = geoip_settings.get("enabled", False) if geoip_settings else False
    if not geoip_enabled:
        return

    if not geoip_service.is_database_available():
        return

    # Get geoip_fields from index pattern
    geoip_fields = index_pattern.geoip_fields or []
    if not geoip_fields:
        return

    # Enrich configured fields
    for field_path in geoip_fields:
        ip_value = get_nested_value(log_doc, field_path)
        if not ip_value or not isinstance(ip_value, str):
            continue

        # Skip private IPs
        if not geoip_service.is_public_ip(ip_value):
            continue

        # Look up GeoIP data
        geo_data = geoip_service.lookup(ip_value)
        if geo_data:
            # Determine geo field path (e.g., source.ip -> source.geo)
            if field_path.endswith(".ip"):
                geo_path = field_path[:-3] + ".geo"
            else:
                geo_path = field_path + "_geo"

            set_nested_value(enriched, geo_path, geo_data)


async def _enrich_ti(
    db: AsyncSession,
    enriched: dict,
    log_doc: dict,
) -> None:
    """Add Threat Intelligence enrichment to the document."""
    try:
        # Check if TI is enabled (at least one source configured)
        ti_manager = await get_ti_manager(db)
        if not ti_manager.enabled_sources:
            return

        # Extract indicators from the log document
        indicators = extract_indicators(log_doc)
        if not indicators:
            return

        # Collect enrichment results
        ti_enrichment: dict[str, Any] = {
            "sources_used": ti_manager.enabled_sources,
            "indicators": [],
        }

        # Enrich each indicator
        for indicator_type, values in indicators.items():
            for value in values:
                try:
                    result = await ti_manager.enrich(value, indicator_type)
                    if result.sources_with_results > 0:
                        ti_enrichment["indicators"].append(result.to_dict())
                except Exception as e:
                    logger.warning(f"TI enrichment failed for {value}: {e}")

        # Only add ti_enrichment if we have results
        if ti_enrichment["indicators"]:
            enriched["ti_enrichment"] = ti_enrichment

    except Exception as e:
        logger.error(f"TI enrichment error: {e}")
