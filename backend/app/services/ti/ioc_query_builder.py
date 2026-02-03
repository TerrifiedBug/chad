"""OpenSearch query builder for Pull Mode IOC detection."""

from typing import Any

from app.services.ti.ioc_index import INDICATOR_INDEX_NAME


class IOCQueryBuilder:
    """Builds OpenSearch join queries for IOC detection."""

    def build_join_query(
        self,
        field_mappings: dict[str, list[str]],
        time_field: str = "@timestamp",
        lookback_minutes: int = 15,
    ) -> dict[str, Any]:
        """Build an OpenSearch query that joins logs against indicator index.

        Args:
            field_mappings: Mapping of IOC types to log field names.
            time_field: Timestamp field for time range filter.
            lookback_minutes: How far back to search (in minutes).

        Returns:
            OpenSearch query body.
        """
        # Build should clauses for each field mapping
        should_clauses = []

        for ioc_type, fields in field_mappings.items():
            for field_name in fields:
                # Terms lookup against indicator index
                clause = {
                    "terms": {
                        field_name: {
                            "index": INDICATOR_INDEX_NAME,
                            "path": "indicator.value",
                            # Filter indicator index to only matching IOC type
                            "query": {
                                "bool": {
                                    "must": [
                                        {"term": {"indicator.type": ioc_type}},
                                        {"range": {"expires_at": {"gte": "now"}}},
                                    ]
                                }
                            },
                        }
                    }
                }
                should_clauses.append(clause)

        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                time_field: {
                                    "gte": f"now-{lookback_minutes}m",
                                }
                            }
                        }
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1 if should_clauses else 0,
                }
            }
        }

        return query

    def build_aggregation_query(
        self,
        field_mappings: dict[str, list[str]],
        time_field: str = "@timestamp",
        lookback_minutes: int = 15,
    ) -> dict[str, Any]:
        """Build query with aggregations to group by matched IOC.

        Args:
            field_mappings: Mapping of IOC types to log field names.
            time_field: Timestamp field for time range filter.
            lookback_minutes: How far back to search.

        Returns:
            OpenSearch query body with aggregations.
        """
        base_query = self.build_join_query(
            field_mappings=field_mappings,
            time_field=time_field,
            lookback_minutes=lookback_minutes,
        )

        # Add aggregations for each field
        aggs = {}
        for ioc_type, fields in field_mappings.items():
            for field_name in fields:
                agg_name = f"ioc_{ioc_type}_{field_name.replace('.', '_')}"
                aggs[agg_name] = {
                    "terms": {
                        "field": field_name,
                        "size": 100,
                    }
                }

        base_query["aggs"] = aggs
        base_query["size"] = 0  # Don't return hits, just aggs

        return base_query
