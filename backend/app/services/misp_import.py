"""MISP import service for browsing events and fetching IOCs."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# MISP threat level ID to name mapping
THREAT_LEVELS = {1: 'High', 2: 'Medium', 3: 'Low', 4: 'Undefined'}


class MISPImportService:
    """Service for browsing MISP events and importing IOCs."""

    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.url,
            headers={
                'Authorization': api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            timeout=timeout,
            verify=verify_ssl,
        )

    async def test_connection(self) -> bool:
        """Test connection to MISP instance."""
        try:
            response = await self._client.get('/servers/getVersion')
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error("MISP connection test failed: %s", type(e).__name__)
            raise

    async def search_events(
        self,
        limit: int = 50,
        date_from: str | None = None,
        date_to: str | None = None,
        threat_levels: list[int] | None = None,
        search_term: str | None = None,
    ) -> list[dict]:
        """Search MISP events with filters."""
        # Build search parameters
        params: dict[str, Any] = {
            'limit': limit,
            'returnFormat': 'json',
        }

        if date_from:
            params['from'] = date_from
        if date_to:
            params['to'] = date_to
        if threat_levels:
            params['threat_level_id'] = threat_levels
        if search_term:
            params['searchinfo'] = search_term

        try:
            response = await self._client.post('/events/restSearch', json=params)
            response.raise_for_status()
            data = response.json()

            events = []
            for event_data in data.get('response', []):
                event = event_data.get('Event', event_data)
                events.append(self._format_event(event))

            return events

        except Exception as e:
            logger.error("MISP event search failed: %s", type(e).__name__)
            raise

    async def get_event_iocs(
        self,
        event_id: str,
        enforce_warninglist: bool = True,
        to_ids_only: bool = True,
    ) -> dict[str, list[dict]]:
        """Get IOCs from an event, grouped by type."""
        try:
            response = await self._client.get(f'/events/view/{event_id}')
            response.raise_for_status()
            data = response.json()

            event = data.get('Event', data)
            attributes = event.get('Attribute', [])

            iocs_by_type: dict[str, list[dict]] = {}

            for attr in attributes:
                # Skip non-IDS attributes if filter enabled
                if to_ids_only and not attr.get('to_ids', False):
                    continue

                # Check warning list status
                warnings = attr.get('warnings', [])
                on_warning_list = bool(warnings)

                ioc_type = attr.get('type', 'unknown')
                if ioc_type not in iocs_by_type:
                    iocs_by_type[ioc_type] = []

                iocs_by_type[ioc_type].append({
                    'id': attr.get('uuid', attr.get('id')),
                    'type': ioc_type,
                    'value': attr.get('value', ''),
                    'comment': attr.get('comment'),
                    'to_ids': attr.get('to_ids', False),
                    'on_warning_list': on_warning_list,
                    'warning_list_name': warnings[0] if warnings else None,
                })

            return iocs_by_type

        except Exception as e:
            logger.error("Failed to get event IOCs: %s", type(e).__name__)
            raise

    async def get_event(self, event_id: str) -> dict:
        """Get a single event's details."""
        try:
            response = await self._client.get(f'/events/view/{event_id}')
            response.raise_for_status()
            data = response.json()
            event = data.get('Event', data)
            return self._format_event(event)
        except Exception as e:
            logger.error("Failed to get event: %s", type(e).__name__)
            raise

    def _format_event(self, event: dict) -> dict:
        """Format event for API response."""
        attributes = event.get('Attribute', [])

        # Count IOCs by type (only IDS-flagged)
        ioc_summary: dict[str, int] = {}
        for attr in attributes:
            if attr.get('to_ids', False):
                ioc_type = attr.get('type', 'unknown')
                ioc_summary[ioc_type] = ioc_summary.get(ioc_type, 0) + 1

        threat_level_id = int(event.get('threat_level_id', 4))

        return {
            'id': event.get('id'),
            'uuid': event.get('uuid'),
            'info': event.get('info', 'Unknown Event'),
            'date': event.get('date', ''),
            'threat_level': THREAT_LEVELS.get(threat_level_id, 'Unknown'),
            'threat_level_id': threat_level_id,
            'ioc_count': sum(ioc_summary.values()),
            'ioc_summary': ioc_summary,
            'tags': [tag.get('name', '') for tag in event.get('Tag', [])],
            'timestamp': event.get('timestamp'),
        }

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()
