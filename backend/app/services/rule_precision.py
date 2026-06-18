"""Per-rule detection-quality aggregation (precision leaderboard).

Pure aggregation over the alerts stored in OpenSearch — no DB schema change.
Runs a single ``terms(rule_id) -> by_status`` aggregation (the same shape as
``AlertService.get_alert_counts``) and derives, per rule:

  - precision  = resolved / (resolved + false_positive)
  - fp_rate    = false_positive / total
  - alerts_per_day = total / window_days

The synchronous OpenSearch call mirrors the rest of the alerts/stats code; on
any failure we degrade to an empty result rather than raising.
"""

from __future__ import annotations

import logging
from typing import Any

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_DAYS = 30
DEFAULT_TOP_N = 50


def build_precision_query(
    index_pattern: str = "chad-alerts-*",
    days: int = DEFAULT_WINDOW_DAYS,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Build the size-0 OpenSearch body for the per-rule precision aggregation."""
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"created_at": {"gte": f"now-{days}d"}}},
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule_id", "size": top_n},
                "aggs": {
                    "by_status": {"terms": {"field": "status", "size": 10}},
                },
            }
        },
    }


def derive_rule_rows(
    aggregation: dict[str, Any], days: int = DEFAULT_WINDOW_DAYS
) -> list[dict[str, Any]]:
    """Derive per-rule precision / fp-rate / volume from an OS aggregation block.

    ``aggregation`` is the ``aggregations`` object returned by OpenSearch for the
    body from :func:`build_precision_query`. Sorted noisiest-first
    (fp_rate desc, then total desc) so the worst offenders surface at the top.
    """
    window_days = days if days > 0 else 1
    buckets = aggregation.get("by_rule", {}).get("buckets", []) if aggregation else []

    rows: list[dict[str, Any]] = []
    for bucket in buckets:
        rule_id = bucket.get("key", "")
        total = bucket.get("doc_count", 0)
        by_status = {
            b["key"]: b["doc_count"]
            for b in bucket.get("by_status", {}).get("buckets", [])
        }
        resolved = by_status.get("resolved", 0)
        false_positive = by_status.get("false_positive", 0)
        open_count = by_status.get("new", 0) + by_status.get("acknowledged", 0)

        decided = resolved + false_positive
        precision_pct = round(100 * resolved / decided, 1) if decided else 0.0
        fp_rate_pct = round(100 * false_positive / total, 1) if total else 0.0
        alerts_per_day = round(total / window_days, 1)

        rows.append(
            {
                "rule_id": rule_id,
                "total": total,
                "resolved": resolved,
                "false_positive": false_positive,
                "open": open_count,
                "precision_pct": precision_pct,
                "fp_rate_pct": fp_rate_pct,
                "alerts_per_day": alerts_per_day,
            }
        )

    rows.sort(key=lambda r: (-r["fp_rate_pct"], -r["total"]))
    return rows
