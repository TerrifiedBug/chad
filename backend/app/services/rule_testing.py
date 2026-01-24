"""
Historical rule testing service.

Allows testing Sigma rules against past log data to see what would have matched.
This is a "dry-run" feature - it doesn't create alerts, just shows matches.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.rule import Rule
from app.services.field_mapping import resolve_mappings
from app.services.sigma import sigma_service


@dataclass
class HistoricalTestResult:
    """Result of running a historical test on a rule."""

    total_scanned: int
    total_matches: int
    matches: list[dict[str, Any]]
    truncated: bool
    query_executed: dict[str, Any] | None = None
    error: str | None = None


async def run_historical_test(
    db: AsyncSession,
    os_client: OpenSearch,
    rule_id: UUID,
    start_date: datetime,
    end_date: datetime,
    limit: int = 500,
) -> HistoricalTestResult:
    """
    Run a historical test for a rule against past log data.

    This translates the Sigma rule to an OpenSearch query, adds a time range
    filter, and executes against the rule's associated index pattern.

    Args:
        db: Database session
        os_client: OpenSearch client
        rule_id: ID of the rule to test
        start_date: Start of time range to search
        end_date: End of time range to search
        limit: Maximum number of matches to return (1-1000)

    Returns:
        HistoricalTestResult with match counts and sample documents
    """
    # Fetch rule with index pattern
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        return HistoricalTestResult(
            total_scanned=0,
            total_matches=0,
            matches=[],
            truncated=False,
            error="Rule not found",
        )

    if rule.index_pattern is None:
        return HistoricalTestResult(
            total_scanned=0,
            total_matches=0,
            matches=[],
            truncated=False,
            error="Rule has no associated index pattern",
        )

    # Translate the Sigma rule
    translation = sigma_service.translate_and_validate(rule.yaml_content)
    if not translation.success:
        errors_str = ", ".join(e.message for e in (translation.errors or []))
        return HistoricalTestResult(
            total_scanned=0,
            total_matches=0,
            matches=[],
            truncated=False,
            error=f"Failed to translate rule: {errors_str}",
        )

    # Get field mappings and re-translate with them
    sigma_fields = list(translation.fields or set())
    field_mappings_dict: dict[str, str] = {}

    if sigma_fields and rule.index_pattern_id:
        resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
        field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

    # Translate with field mappings applied
    if field_mappings_dict:
        translation = sigma_service.translate_with_mappings(
            rule.yaml_content, field_mappings_dict
        )
        if not translation.success:
            errors_str = ", ".join(e.message for e in (translation.errors or []))
            return HistoricalTestResult(
                total_scanned=0,
                total_matches=0,
                matches=[],
                truncated=False,
                error=f"Failed to translate rule with mappings: {errors_str}",
            )

    # Build the final query with time range filter
    # The Sigma translation returns {"query": {"query_string": {"query": "..."}}}
    sigma_query = translation.query
    if sigma_query is None:
        return HistoricalTestResult(
            total_scanned=0,
            total_matches=0,
            matches=[],
            truncated=False,
            error="Translation produced no query",
        )

    # Extract the inner query
    inner_query = sigma_query.get("query", sigma_query)

    # Create a bool query that combines Sigma query with time range
    # Use @timestamp as the default time field (common in OpenSearch/Elastic logs)
    combined_query = {
        "query": {
            "bool": {
                "must": [inner_query],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_date.isoformat(),
                                "lte": end_date.isoformat(),
                            }
                        }
                    }
                ],
            }
        }
    }

    index_pattern = rule.index_pattern.pattern

    try:
        # First, get total documents in the time range (for context)
        count_all_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_date.isoformat(),
                        "lte": end_date.isoformat(),
                    }
                }
            }
        }
        count_all_result = os_client.count(index=index_pattern, body=count_all_query)
        total_scanned = count_all_result.get("count", 0)

        # Get count of matching documents
        count_result = os_client.count(index=index_pattern, body=combined_query)
        total_matches = count_result.get("count", 0)

        # Get sample matching documents
        search_body = {
            **combined_query,
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        search_result = os_client.search(index=index_pattern, body=search_body)

        # Extract matches
        hits = search_result.get("hits", {}).get("hits", [])
        matches = []
        for hit in hits:
            match_doc = {
                "_id": hit.get("_id"),
                "_index": hit.get("_index"),
                "_source": hit.get("_source", {}),
            }
            matches.append(match_doc)

        truncated = total_matches > limit

        return HistoricalTestResult(
            total_scanned=total_scanned,
            total_matches=total_matches,
            matches=matches,
            truncated=truncated,
            query_executed=combined_query,
        )

    except Exception as e:
        return HistoricalTestResult(
            total_scanned=0,
            total_matches=0,
            matches=[],
            truncated=False,
            error=f"OpenSearch query failed: {str(e)}",
            query_executed=combined_query,
        )
