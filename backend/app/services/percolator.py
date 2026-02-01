"""
Percolator index management for rule deployment.

Each index pattern has a corresponding percolator index:
- Index pattern: logs-windows-*
- Percolator index: percolator-logs-windows

The percolator index stores:
- query: The percolator query (OpenSearch DSL)
- rule_id: UUID of the rule in PostgreSQL
- rule_title: For quick identification
- severity: For alert prioritization
- tags: MITRE ATT&CK tags
- enabled: Whether rule is active
"""

from datetime import datetime, timezone
from typing import Any

from opensearchpy import OpenSearch

PERCOLATOR_MAPPING = {
    "settings": {
        "index.mapping.total_fields.limit": 10000,  # Allow many fields
    },
    "mappings": {
        "dynamic": True,  # Allow dynamic field creation for query validation
        "properties": {
            "query": {"type": "percolator"},
            "rule_id": {"type": "keyword"},
            "rule_title": {"type": "text"},
            "severity": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "enabled": {"type": "boolean"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
        }
    }
}


class PercolatorService:
    def __init__(self, client: OpenSearch):
        self.client = client

    def get_percolator_index_name(self, index_pattern_name: str) -> str:
        """Convert index pattern name to percolator index name."""
        # Sanitize: remove wildcards, replace special chars
        sanitized = index_pattern_name.replace("*", "").replace("-*", "").rstrip("-")
        return f"chad-percolator-{sanitized}"

    def ensure_percolator_index(
        self, index_name: str, source_index_pattern: str | None = None
    ) -> None:
        """
        Create percolator index if it doesn't exist, and sync field mappings from source.

        If source_index_pattern is provided, copies field mappings from the source
        indices so percolator queries can be validated against the correct fields.
        This also updates mappings on existing percolator indices to handle new fields.
        """
        index_exists = self.client.indices.exists(index=index_name)

        if not index_exists:
            # Start with base mapping for new index
            mapping = {
                "settings": {
                    "index.mapping.total_fields.limit": 10000,
                },
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "query": {"type": "percolator"},
                        "rule_id": {"type": "keyword"},
                        "rule_title": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "enabled": {"type": "boolean"},
                        "created_at": {"type": "date"},
                        "updated_at": {"type": "date"},
                    }
                }
            }

            # Copy field mappings from source index if provided
            if source_index_pattern:
                try:
                    source_mappings = self.client.indices.get_mapping(index=source_index_pattern)
                    if source_mappings:
                        first_index = list(source_mappings.keys())[0]
                        source_props = source_mappings[first_index].get("mappings", {}).get("properties", {})
                        mapping["mappings"]["properties"].update(source_props)
                except Exception:
                    pass

            self.client.indices.create(index=index_name, body=mapping)
        elif source_index_pattern:
            # Index exists - update mappings to include any new fields from source
            try:
                source_mappings = self.client.indices.get_mapping(index=source_index_pattern)
                if source_mappings:
                    first_index = list(source_mappings.keys())[0]
                    source_props = source_mappings[first_index].get("mappings", {}).get("properties", {})
                    if source_props:
                        self.client.indices.put_mapping(
                            index=index_name,
                            body={"properties": source_props}
                        )
            except Exception:
                # If mapping update fails, continue - deployment will fail with clear error
                pass

    def deploy_rule(
        self,
        percolator_index: str,
        rule_id: str,
        query: dict[str, Any],
        title: str,
        severity: str,
        tags: list[str],
    ) -> None:
        """Deploy or update a rule in the percolator index.

        Args:
            percolator_index: Name of the percolator index
            rule_id: Unique rule identifier
            query: Translated percolator query
            title: Rule title
            severity: Rule severity
            tags: Rule tags

        Returns:
            None
        """
        now = datetime.now(timezone.utc).isoformat()

        # Check if rule already exists to preserve created_at
        existing = self.get_deployed_rule(percolator_index, rule_id)
        created_at = existing.get("created_at", now) if existing else now

        doc = {
            "query": query,
            "rule_id": rule_id,
            "rule_title": title,
            "severity": severity,
            "tags": tags,
            "created_at": created_at,
            "updated_at": now,
        }
        self.client.index(
            index=percolator_index,
            id=rule_id,  # Use rule UUID as doc ID for easy updates
            body=doc,
            refresh=True,
        )

    def undeploy_rule(self, percolator_index: str, rule_id: str) -> bool:
        """
        Remove a rule from the percolator index.

        Returns:
            True if the rule was deleted, False if it didn't exist.
        """
        try:
            result = self.client.delete(
                index=percolator_index,
                id=rule_id,
                refresh=True,
            )
            return result.get("result") == "deleted"
        except Exception:
            # Rule didn't exist
            return False

    def update_rule_status(
        self, percolator_index: str, rule_id: str, enabled: bool
    ) -> bool:
        """
        Update the enabled status of a deployed rule.

        Returns:
            True if the rule was updated, False if it doesn't exist.
        """
        try:
            self.client.update(
                index=percolator_index,
                id=rule_id,
                body={
                    "doc": {
                        "enabled": enabled,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                },
                refresh=True,
            )
            return True
        except Exception:
            return False

    def get_deployed_rule(
        self, percolator_index: str, rule_id: str
    ) -> dict[str, Any] | None:
        """Get a deployed rule document."""
        try:
            result = self.client.get(index=percolator_index, id=rule_id)
            return result["_source"]
        except Exception:
            return None

    def is_rule_deployed(self, percolator_index: str, rule_id: str) -> bool:
        """Check if a rule is deployed in the percolator index."""
        try:
            return self.client.exists(index=percolator_index, id=rule_id)
        except Exception:
            return False

    def undeploy_all_rules(self, percolator_index: str) -> int:
        """
        Remove all rules from a percolator index.

        Used when transitioning an index pattern from push to pull mode.

        Returns:
            Number of rules deleted.
        """
        try:
            # Check if index exists
            if not self.client.indices.exists(index=percolator_index):
                return 0

            # Delete all documents using delete_by_query
            result = self.client.delete_by_query(
                index=percolator_index,
                body={"query": {"match_all": {}}},
                refresh=True,
            )
            return result.get("deleted", 0)
        except Exception:
            return 0

    def get_deployed_rule_count(self, percolator_index: str) -> int:
        """Get the number of deployed rules in a percolator index."""
        try:
            if not self.client.indices.exists(index=percolator_index):
                return 0
            result = self.client.count(index=percolator_index)
            return result.get("count", 0)
        except Exception:
            return 0
