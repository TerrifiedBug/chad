"""
Alert enrichment service.

Enriches alert data with additional context like GeoIP and Threat Intelligence.
"""
import ipaddress
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern
from app.services.geoip import geoip_service
from app.services.settings import get_setting
from app.services.system_log import LogCategory, system_log_service
from app.services.ti import TIEnrichmentManager, TIIndicatorType

logger = logging.getLogger(__name__)

# Mapping of field name hints to indicator types
INDICATOR_TYPE_HINTS = {
    # IP fields
    "ip": TIIndicatorType.IP,
    "ip_address": TIIndicatorType.IP,
    "ipaddress": TIIndicatorType.IP,
    "src_ip": TIIndicatorType.IP,
    "dst_ip": TIIndicatorType.IP,
    "source_ip": TIIndicatorType.IP,
    "dest_ip": TIIndicatorType.IP,
    # Domain fields
    "domain": TIIndicatorType.DOMAIN,
    "hostname": TIIndicatorType.DOMAIN,
    "host": TIIndicatorType.DOMAIN,
    "fqdn": TIIndicatorType.DOMAIN,
    # URL fields
    "url": TIIndicatorType.URL,
    "uri": TIIndicatorType.URL,
    # Hash fields
    "md5": TIIndicatorType.HASH_MD5,
    "sha1": TIIndicatorType.HASH_SHA1,
    "sha256": TIIndicatorType.HASH_SHA256,
    "hash_md5": TIIndicatorType.HASH_MD5,
    "hash_sha1": TIIndicatorType.HASH_SHA1,
    "hash_sha256": TIIndicatorType.HASH_SHA256,
    "file_hash": TIIndicatorType.HASH_SHA256,  # Default to SHA256
}


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


def infer_indicator_type(field_path: str) -> TIIndicatorType | None:
    """
    Infer the indicator type from a field path.

    Uses the last component of the path to guess the type.
    """
    # Get the last part of the path (e.g., "source.ip" -> "ip")
    field_name = field_path.split(".")[-1].lower()

    # Check exact match first
    if field_name in INDICATOR_TYPE_HINTS:
        return INDICATOR_TYPE_HINTS[field_name]

    # Check if field name contains a known hint
    for hint, indicator_type in INDICATOR_TYPE_HINTS.items():
        if hint in field_name:
            return indicator_type

    # Default to IP for unknown fields (most common use case)
    return TIIndicatorType.IP


def extract_field_indicators(
    doc: dict,
    field_configs: list[dict],
) -> list[tuple[str, str, TIIndicatorType]]:
    """
    Extract indicator values from specific fields in a document.

    Args:
        doc: The log document.
        field_configs: List of field configs with explicit type.
            Format: [{"field": "source.ip", "type": "ip"}, ...]

    Returns:
        List of tuples: (field_path, value, indicator_type)
    """
    results: list[tuple[str, str, TIIndicatorType]] = []

    for config in field_configs:
        # Handle both old format (string) and new format (dict with field/type)
        if isinstance(config, str):
            field_path = config
            indicator_type = infer_indicator_type(field_path)
        elif isinstance(config, dict):
            field_path = config.get("field", "")
            type_str = config.get("type", "")
            try:
                indicator_type = TIIndicatorType(type_str)
            except ValueError:
                # Fall back to inference if type is invalid
                indicator_type = infer_indicator_type(field_path)
        else:
            continue

        if not field_path or not indicator_type:
            continue

        value = get_nested_value(doc, field_path)
        if not value or not isinstance(value, str):
            continue

        # Skip empty strings
        if not value.strip():
            continue

        # Skip private IPs
        if indicator_type == TIIndicatorType.IP and not is_public_ip(value):
            continue

        results.append((field_path, value, indicator_type))

    return results


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
    await _enrich_ti(db, enriched, log_doc, index_pattern)

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
    index_pattern: IndexPattern,
) -> None:
    """Add Threat Intelligence enrichment to the document."""
    try:
        # Get TI configuration from index pattern
        ti_config = index_pattern.ti_config or {}
        if not ti_config:
            return

        # Get the TI manager
        ti_manager = await get_ti_manager(db)
        if not ti_manager.enabled_sources:
            return

        # Collect all indicators to look up, grouped by source
        ti_enrichment: dict[str, Any] = {
            "sources_used": [],
            "indicators": [],
        }

        # Track which values we've already looked up to avoid duplicates
        seen_indicators: set[str] = set()

        # Process each TI source configuration
        for source_name, source_config in ti_config.items():
            if not isinstance(source_config, dict):
                continue

            # Check if this source is enabled for this index pattern
            if not source_config.get("enabled", False):
                continue

            # Check if this source is globally enabled
            if source_name not in ti_manager.enabled_sources:
                continue

            # Get the fields configured for this source
            fields = source_config.get("fields", [])
            if not fields:
                continue

            # Extract indicators from configured fields
            indicators = extract_field_indicators(log_doc, fields)

            # Look up each indicator
            for field_path, value, indicator_type in indicators:
                # Create unique key to avoid duplicate lookups
                indicator_key = f"{value}:{indicator_type.value}"
                if indicator_key in seen_indicators:
                    continue
                seen_indicators.add(indicator_key)

                try:
                    result = await ti_manager.enrich(value, indicator_type)
                    if result.sources_with_results > 0:
                        result_dict = result.to_dict()
                        result_dict["field"] = field_path  # Add source field info
                        ti_enrichment["indicators"].append(result_dict)
                except Exception as e:
                    logger.warning(f"TI enrichment failed for {value}: {e}")
                    await system_log_service.log_warning(
                        db,
                        category=LogCategory.INTEGRATIONS,
                        service="enrichment",
                        message=f"TI enrichment failed for indicator: {value}",
                        details={"error": str(e), "error_type": type(e).__name__, "indicator": value}
                    )

            # Track which sources were used
            if source_name not in ti_enrichment["sources_used"]:
                ti_enrichment["sources_used"].append(source_name)

        # Only add ti_enrichment if we have results
        if ti_enrichment["indicators"]:
            enriched["ti_enrichment"] = ti_enrichment

    except Exception as e:
        logger.error(f"TI enrichment error: {e}")
        await system_log_service.log_error(
            db,
            category=LogCategory.INTEGRATIONS,
            service="enrichment",
            message=f"TI enrichment operation failed: {str(e)}",
            details={"error": str(e), "error_type": type(e).__name__}
        )
