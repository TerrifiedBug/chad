"""OpenSearch indicator index service for Pull Mode detection."""

import logging
from typing import Any

from app.services.ti.ioc_types import IOCRecord

logger = logging.getLogger(__name__)

INDICATOR_INDEX_NAME = "chad-indicators"

INDICATOR_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "indicator.type": {"type": "keyword"},
            "indicator.value": {"type": "keyword"},
            "misp.event_id": {"type": "keyword"},
            "misp.event_uuid": {"type": "keyword"},
            "misp.event_info": {"type": "text"},
            "misp.attribute_uuid": {"type": "keyword"},
            "misp.threat_level": {"type": "keyword"},
            "misp.tags": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "expires_at": {"type": "date"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


class IOCIndexService:
    """Service for managing OpenSearch indicator index."""

    def __init__(self, os_client: Any):
        """Initialize the IOC index service.

        Args:
            os_client: OpenSearch client instance.
        """
        self.client = os_client
        self.index_name = INDICATOR_INDEX_NAME

    async def ensure_index(self) -> None:
        """Ensure the indicator index exists, create if not."""
        if self.client.indices.exists(self.index_name):
            logger.debug("Indicator index %s already exists", self.index_name)
            return

        self.client.indices.create(
            index=self.index_name,
            body=INDICATOR_INDEX_MAPPING,
        )
        logger.info("Created indicator index %s", self.index_name)

    async def bulk_index_iocs(self, records: list[IOCRecord]) -> int:
        """Bulk index IOC records to OpenSearch.

        Args:
            records: List of IOC records to index.

        Returns:
            Number of records indexed.
        """
        if not records:
            return 0

        # Build bulk request body
        bulk_body = []
        for record in records:
            # Use attribute UUID as document ID for idempotent updates
            action = {
                "index": {
                    "_index": self.index_name,
                    "_id": record.misp_attribute_uuid,
                }
            }
            bulk_body.append(action)
            bulk_body.append(record.to_opensearch_doc())

        response = self.client.bulk(body=bulk_body)

        if response.get("errors"):
            error_count = sum(
                1 for item in response.get("items", [])
                if "error" in item.get("index", {})
            )
            logger.warning("Bulk index had %d errors", error_count)

        indexed_count = len(records)
        logger.info("Indexed %d IOCs to OpenSearch", indexed_count)
        return indexed_count

    async def delete_expired_iocs(self) -> int:
        """Delete IOCs that have expired.

        Returns:
            Number of IOCs deleted.
        """
        response = self.client.delete_by_query(
            index=self.index_name,
            body={
                "query": {
                    "range": {
                        "expires_at": {"lt": "now"}
                    }
                }
            },
        )
        deleted = response.get("deleted", 0)
        logger.info("Deleted %d expired IOCs from index", deleted)
        return deleted

    async def get_ioc_count(self) -> int:
        """Get total count of IOCs in index.

        Returns:
            Number of IOCs in index.
        """
        response = self.client.count(index=self.index_name)
        return response.get("count", 0)

    async def clear_all_iocs(self) -> int:
        """Delete all IOCs from index.

        Returns:
            Number of IOCs deleted.
        """
        response = self.client.delete_by_query(
            index=self.index_name,
            body={"query": {"match_all": {}}},
        )
        deleted = response.get("deleted", 0)
        logger.info("Cleared %d IOCs from indicator index", deleted)
        return deleted
