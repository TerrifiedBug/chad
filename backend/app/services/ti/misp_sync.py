"""MISP IOC synchronization service."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.services.ti.ioc_types import IOCRecord, IOCType

logger = logging.getLogger(__name__)

# MISP threat level ID to name mapping
THREAT_LEVEL_MAP = {
    "1": "high",
    "2": "medium",
    "3": "low",
    "4": "undefined",
}


class MISPIOCFetcher:
    """Fetches IOCs from MISP for sync to Redis/OpenSearch."""

    def __init__(
        self,
        api_key: str,
        instance_url: str,
        verify_tls: bool = True,
        timeout: int = 60,
    ):
        """Initialize the MISP IOC fetcher.

        Args:
            api_key: MISP API key.
            instance_url: Base URL of MISP instance.
            verify_tls: Whether to verify TLS certificates.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.instance_url = instance_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.instance_url,
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
            verify=verify_tls,
        )

    def _map_threat_level(self, level_id: str) -> str:
        """Map MISP threat level ID to name."""
        return THREAT_LEVEL_MAP.get(level_id, "unknown")

    def _map_misp_type_to_ioc_type(self, misp_type: str) -> IOCType | None:
        """Map MISP attribute type to IOCType enum."""
        mapping = {
            "ip-dst": IOCType.IP_DST,
            "ip-src": IOCType.IP_SRC,
            "domain": IOCType.DOMAIN,
            "md5": IOCType.MD5,
            "sha1": IOCType.SHA1,
            "sha256": IOCType.SHA256,
            "url": IOCType.URL,
        }
        return mapping.get(misp_type)

    def _has_excessive_false_positives(self, attr: dict) -> bool:
        """Check if attribute has more false positive sightings than true sightings.

        MISP sighting types:
        - 0: Regular sighting (confirmed observation)
        - 1: False positive
        - 2: Expiration (not relevant here)

        Args:
            attr: MISP attribute dict with optional Sighting key.

        Returns:
            True if FP sightings >= regular sightings, False otherwise.
        """
        sightings = attr.get("Sighting", [])
        if not sightings:
            return False

        true_sightings = 0
        false_positives = 0

        for sighting in sightings:
            sighting_type = int(sighting.get("type", 0))
            if sighting_type == 0:
                true_sightings += 1
            elif sighting_type == 1:
                false_positives += 1

        # Filter if FP sightings >= true sightings (and there are FPs)
        return false_positives > 0 and false_positives >= true_sightings

    async def fetch_iocs(
        self,
        threat_levels: list[str] | None = None,
        ioc_types: list[IOCType] | None = None,
        max_age_days: int = 30,
        tags: list[str] | None = None,
        ttl_days: int = 30,
        filter_false_positives: bool = True,
    ) -> list[IOCRecord]:
        """Fetch IOCs from MISP.

        Args:
            threat_levels: Filter by threat level names (high, medium, low).
            ioc_types: Filter by IOC types.
            max_age_days: Only fetch IOCs from last N days.
            tags: Filter by MISP tags.
            ttl_days: TTL for IOCs (for expires_at calculation).
            filter_false_positives: Filter out IOCs with more FP sightings than true sightings.

        Returns:
            List of IOCRecord objects.
        """
        # Build request body
        request_body: dict[str, Any] = {
            "to_ids": True,
            "includeEventTags": True,
            "includeSightings": filter_false_positives,  # Include sightings for FP filtering
            "timestamp": int((datetime.now(UTC) - timedelta(days=max_age_days)).timestamp()),
        }

        # Add type filter if specified
        if ioc_types:
            misp_types = []
            for ioc_type in ioc_types:
                misp_types.append(ioc_type.value)
            request_body["type"] = misp_types

        # Add tag filter if specified
        if tags:
            request_body["tags"] = tags

        # Add threat level filter
        if threat_levels:
            level_ids = []
            for level in threat_levels:
                for lid, lname in THREAT_LEVEL_MAP.items():
                    if lname == level:
                        level_ids.append(lid)
            if level_ids:
                request_body["threat_level_id"] = level_ids

        try:
            response = await self._client.post(
                "/attributes/restSearch",
                json=request_body,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error("Failed to fetch IOCs from MISP: %s", e)
            raise

        attributes = data.get("response", {}).get("Attribute", [])
        records: list[IOCRecord] = []
        expires_at = datetime.now(UTC) + timedelta(days=ttl_days)
        filtered_fp_count = 0

        for attr in attributes:
            misp_type = attr.get("type")
            ioc_type = self._map_misp_type_to_ioc_type(misp_type)

            if ioc_type is None:
                continue

            # Filter out IOCs with excessive false positive sightings
            if filter_false_positives and self._has_excessive_false_positives(attr):
                filtered_fp_count += 1
                continue

            event = attr.get("Event", {})
            event_tags = event.get("Tag", [])
            tag_names = [t.get("name", "") for t in event_tags]

            record = IOCRecord(
                ioc_type=ioc_type,
                value=attr.get("value", ""),
                misp_event_id=str(attr.get("event_id", "")),
                misp_event_uuid=event.get("uuid", ""),
                misp_attribute_uuid=attr.get("uuid", ""),
                misp_event_info=event.get("info"),
                threat_level=self._map_threat_level(str(event.get("threat_level_id", ""))),
                tags=tag_names,
                expires_at=expires_at,
            )
            records.append(record)

        if filtered_fp_count > 0:
            logger.info(
                "Filtered %d IOCs with excessive false positives",
                filtered_fp_count
            )
        logger.info("Fetched %d IOCs from MISP", len(records))
        return records

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
