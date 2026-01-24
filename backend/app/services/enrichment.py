"""
Alert enrichment service.

Enriches alert data with additional context like GeoIP information.
"""
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern
from app.services.geoip import geoip_service
from app.services.settings import get_setting

logger = logging.getLogger(__name__)


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

    # Check if GeoIP is enabled
    geoip_settings = await get_setting(db, "geoip")
    geoip_enabled = geoip_settings.get("enabled", False) if geoip_settings else False
    if not geoip_enabled:
        return enriched

    if not geoip_service.is_database_available():
        return enriched

    # Get geoip_fields from index pattern
    geoip_fields = index_pattern.geoip_fields or []
    if not geoip_fields:
        return enriched

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

    return enriched
