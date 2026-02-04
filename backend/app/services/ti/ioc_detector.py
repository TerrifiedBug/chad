"""IOC detection service for Push Mode."""

import logging
from dataclasses import dataclass, field
from typing import Any

from app.services.ti.ioc_cache import IOCCache
from app.services.ti.ioc_types import IOCType

logger = logging.getLogger(__name__)


@dataclass
class IOCMatch:
    """A matched IOC in a log document."""

    ioc_type: IOCType
    value: str
    field_name: str
    misp_event_id: str
    misp_event_uuid: str | None = None
    misp_attribute_uuid: str | None = None
    misp_event_info: str | None = None
    threat_level: str = "unknown"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for alert enrichment."""
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "field_name": self.field_name,
            "misp_event_id": self.misp_event_id,
            "misp_event_uuid": self.misp_event_uuid,
            "misp_attribute_uuid": self.misp_attribute_uuid,
            "misp_event_info": self.misp_event_info,
            "threat_level": self.threat_level,
            "tags": self.tags,
        }


class IOCDetector:
    """Detects IOCs in log documents using Redis cache."""

    def __init__(self):
        """Initialize the IOC detector."""
        self.cache = IOCCache()

    def _get_nested_value(self, doc: dict, field_path: str) -> str | None:
        """Extract a nested value from a document using dot notation.

        Args:
            doc: The document to extract from.
            field_path: Dot-separated path (e.g., "winlog.event_data.DestinationIp")

        Returns:
            The value at the path, or None if not found.
        """
        # First check if the full path exists as a literal key (e.g., "destination.ip")
        if field_path in doc:
            value = doc[field_path]
            if isinstance(value, str):
                return value
            return None

        # Try nested lookup using dot notation
        parts = field_path.split(".")
        current = doc

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        if isinstance(current, str):
            return current
        return None

    async def detect_iocs(
        self,
        log: dict[str, Any],
        field_mappings: dict[str, list[str]],
    ) -> list[IOCMatch]:
        """Detect IOCs in a log document.

        Args:
            log: The log document to check.
            field_mappings: Mapping of IOC types to log field names.

        Returns:
            List of IOCMatch objects for any matches found.
        """
        # Build list of (ioc_type, value, field_name) to look up
        lookups: list[tuple[IOCType, str, str]] = []

        for ioc_type_str, fields in field_mappings.items():
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                continue

            for field_name in fields:
                value = self._get_nested_value(log, field_name)
                if value:
                    lookups.append((ioc_type, value, field_name))

        if not lookups:
            return []

        # Bulk lookup in Redis
        lookup_pairs = [(ioc_type, value) for ioc_type, value, _ in lookups]
        results = await self.cache.bulk_lookup_iocs(lookup_pairs)

        # Build matches from results
        matches: list[IOCMatch] = []
        for i, result in enumerate(results):
            if result is not None:
                ioc_type, value, field_name = lookups[i]
                match = IOCMatch(
                    ioc_type=ioc_type,
                    value=value,
                    field_name=field_name,
                    misp_event_id=result.get("misp_event_id", ""),
                    misp_event_uuid=result.get("misp_event_uuid"),
                    misp_attribute_uuid=result.get("misp_attribute_uuid"),
                    misp_event_info=result.get("misp_event_info"),
                    threat_level=result.get("threat_level", "unknown"),
                    tags=result.get("tags", []),
                )
                matches.append(match)

        return matches
