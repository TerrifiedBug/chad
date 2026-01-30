"""Batch percolation service for efficient log matching."""

import logging
from typing import Any

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


def batch_percolate_logs(
    client: OpenSearch,
    percolator_index: str,
    logs: list[dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:
    """
    Percolate multiple logs in a single OpenSearch call.

    Uses OpenSearch's multi-document percolate feature to match all logs
    against all rules in a single query, significantly reducing network
    round trips compared to individual percolate calls.

    Args:
        client: OpenSearch client
        percolator_index: Index containing percolator rules
        logs: List of log documents to match

    Returns:
        Dict mapping log index (0-based) to list of matching rule documents
    """
    if not logs:
        return {}

    # Build multi-document percolate query
    query = {
        "query": {
            "percolate": {
                "field": "query",
                "documents": logs,
            }
        }
    }

    try:
        result = client.search(index=percolator_index, body=query)

        # Group matches by document slot
        matches_by_log: dict[int, list[dict[str, Any]]] = {}

        for hit in result.get("hits", {}).get("hits", []):
            # _percolator_document_slot tells us which log matched
            slots = hit.get("fields", {}).get("_percolator_document_slot", [])
            rule_doc = hit["_source"]

            for slot in slots:
                if slot not in matches_by_log:
                    matches_by_log[slot] = []
                matches_by_log[slot].append(rule_doc)

        logger.debug(
            f"Batch percolate: {len(logs)} logs, "
            f"{sum(len(m) for m in matches_by_log.values())} matches"
        )

        return matches_by_log

    except Exception as e:
        logger.error(f"Batch percolate failed: {e}")
        return {}
