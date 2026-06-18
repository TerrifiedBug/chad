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
