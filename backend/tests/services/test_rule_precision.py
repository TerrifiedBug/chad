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


from app.services.rule_precision import derive_rule_rows


def _agg(buckets):
    return {"by_rule": {"buckets": buckets}}


def test_derive_rule_rows_precision_and_fp_rate():
    agg = _agg([
        {
            "key": "rule-a",
            "doc_count": 100,
            "by_status": {"buckets": [
                {"key": "resolved", "doc_count": 60},
                {"key": "false_positive", "doc_count": 20},
                {"key": "new", "doc_count": 15},
                {"key": "acknowledged", "doc_count": 5},
            ]},
        },
    ])
    rows = derive_rule_rows(agg, days=30)
    row = rows[0]
    assert row["rule_id"] == "rule-a"
    assert row["total"] == 100
    assert row["resolved"] == 60
    assert row["false_positive"] == 20
    assert row["open"] == 20  # new + acknowledged
    # precision = resolved / (resolved + false_positive) = 60 / 80 = 75.0
    assert row["precision_pct"] == 75.0
    # fp_rate = false_positive / total = 20 / 100 = 20.0
    assert row["fp_rate_pct"] == 20.0
    # alerts_per_day = 100 / 30 = 3.3
    assert row["alerts_per_day"] == 3.3


def test_derive_rule_rows_handles_zero_denominators():
    agg = _agg([
        {
            "key": "rule-untriaged",
            "doc_count": 10,
            "by_status": {"buckets": [{"key": "new", "doc_count": 10}]},
        },
    ])
    rows = derive_rule_rows(agg, days=30)
    row = rows[0]
    # No resolved/false_positive => precision undefined => 0.0, fp_rate 0.0
    assert row["precision_pct"] == 0.0
    assert row["fp_rate_pct"] == 0.0
    assert row["open"] == 10


def test_derive_rule_rows_sorted_noisiest_first():
    agg = _agg([
        {"key": "clean", "doc_count": 50, "by_status": {"buckets": [
            {"key": "resolved", "doc_count": 50}]}},
        {"key": "noisy", "doc_count": 50, "by_status": {"buckets": [
            {"key": "false_positive", "doc_count": 40}, {"key": "resolved", "doc_count": 10}]}},
    ])
    rows = derive_rule_rows(agg, days=30)
    assert [r["rule_id"] for r in rows] == ["noisy", "clean"]


def test_derive_rule_rows_empty():
    assert derive_rule_rows({"by_rule": {"buckets": []}}, days=30) == []
    assert derive_rule_rows({}, days=30) == []
