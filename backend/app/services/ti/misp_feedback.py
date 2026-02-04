"""MISP feedback service for sightings and event creation."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SightingResult:
    """Result of recording a sighting."""

    success: bool
    sighting_id: str | None = None
    error: str | None = None


@dataclass
class EventCreationResult:
    """Result of creating a MISP event."""

    success: bool
    event_id: str | None = None
    event_uuid: str | None = None
    error: str | None = None


class MISPFeedbackService:
    """Service for sending feedback to MISP."""

    def __init__(self, client: httpx.AsyncClient):
        """Initialize the feedback service.

        Args:
            client: Configured httpx AsyncClient for MISP API.
        """
        self._client = client

    async def record_sighting(
        self,
        attribute_uuid: str,
        source: str,
        timestamp: datetime,
        sighting_type: int = 0,
    ) -> SightingResult:
        """Record a sighting in MISP.

        Args:
            attribute_uuid: UUID of the attribute that was sighted.
            source: Source of the sighting (e.g., "CHAD").
            timestamp: When the sighting occurred.
            sighting_type: Type of sighting (0=sighting, 1=false positive).

        Returns:
            SightingResult with success status.
        """
        try:
            response = await self._client.post(
                f"/sightings/add/{attribute_uuid}",
                json={
                    "source": source,
                    "timestamp": int(timestamp.timestamp()),
                    "type": sighting_type,
                },
            )
            response.raise_for_status()
            data = response.json()

            sighting_id = data.get("Sighting", {}).get("id")
            logger.info(
                "Recorded sighting %s for attribute %s",
                sighting_id,
                attribute_uuid,
            )

            return SightingResult(success=True, sighting_id=sighting_id)

        except Exception as e:
            logger.error("Failed to record sighting: %s", e)
            return SightingResult(success=False, error=str(e))

    async def create_event(
        self,
        info: str,
        threat_level: int = 2,
        distribution: int = 0,
        analysis: int = 0,
        tags: list[str] | None = None,
        attributes: list[dict[str, Any]] | None = None,
    ) -> EventCreationResult:
        """Create a new MISP event.

        Args:
            info: Event description/title.
            threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined.
            distribution: 0=Your org, 1=Community, 2=Connected, 3=All.
            analysis: 0=Initial, 1=Ongoing, 2=Complete.
            tags: List of tag names to apply.
            attributes: List of attribute dicts to add.

        Returns:
            EventCreationResult with event ID/UUID.
        """
        try:
            # Create the event
            event_data = {
                "Event": {
                    "info": info,
                    "threat_level_id": threat_level,
                    "distribution": distribution,
                    "analysis": analysis,
                }
            }

            response = await self._client.post(
                "/events/add",
                json=event_data,
            )
            response.raise_for_status()
            data = response.json()

            event = data.get("Event", {})
            event_id = event.get("id")
            event_uuid = event.get("uuid")

            logger.info("Created MISP event %s: %s", event_id, info)

            # Add tags if specified
            if tags and event_id:
                for tag in tags:
                    try:
                        await self._client.post(
                            f"/events/addTag/{event_id}/{tag}",
                        )
                    except Exception as e:
                        logger.warning("Failed to add tag %s: %s", tag, e)

            # Add attributes if specified
            if attributes and event_id:
                for attr in attributes:
                    try:
                        await self._client.post(
                            f"/attributes/add/{event_id}",
                            json={"Attribute": attr},
                        )
                    except Exception as e:
                        logger.warning("Failed to add attribute: %s", e)

            return EventCreationResult(
                success=True,
                event_id=event_id,
                event_uuid=event_uuid,
            )

        except Exception as e:
            logger.error("Failed to create MISP event: %s", e)
            return EventCreationResult(success=False, error=str(e))
