"""Tests for the per-rule precision aggregation service (app.services.rule_precision)."""

from app.services.rule_precision import build_precision_query


def test_build_precision_query_shape():
    body = build_precision_query(days=30, top_n=25)
    assert body["size"] == 0
    assert body["track_total_hits"] is True
    # Time-bounded to the window.
    rng = body["query"]["bool"]["filter"][0]["range"]["created_at"]
    assert rng["gte"] == "now-30d"
    # terms(rule_id) -> by_status nested terms.
    by_rule = body["aggs"]["by_rule"]["terms"]
    assert by_rule["field"] == "rule_id"
    assert by_rule["size"] == 25
    assert body["aggs"]["by_rule"]["aggs"]["by_status"]["terms"]["field"] == "status"


def test_build_precision_query_defaults():
    body = build_precision_query()
    assert body["query"]["bool"]["filter"][0]["range"]["created_at"]["gte"] == "now-30d"
    assert body["aggs"]["by_rule"]["terms"]["size"] == 50
