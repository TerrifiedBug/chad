"""AlertService.get_alerts / get_alert_counts: filter→query construction.

Covers the exclude_status filter and the track_total_hits flag (exact totals
past OpenSearch's default 10k cap). The client is mocked so we assert the query
body handed to OpenSearch rather than hitting a live cluster.
"""

from unittest.mock import MagicMock

from app.services.alerts import AlertService


def _service():
    client = MagicMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    return AlertService(client), client


def test_get_alerts_sets_track_total_hits():
    svc, client = _service()
    svc.get_alerts()
    body = client.search.call_args.kwargs["body"]
    assert body["track_total_hits"] is True


def test_get_alerts_no_filters_matches_all():
    svc, client = _service()
    svc.get_alerts()
    body = client.search.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}


def test_get_alerts_exclude_status_goes_to_must_not():
    svc, client = _service()
    svc.get_alerts(exclude_status=["false_positive", "resolved"])
    body = client.search.call_args.kwargs["body"]
    must_not = body["query"]["bool"]["must_not"]
    assert {"term": {"status": "false_positive"}} in must_not
    assert {"term": {"status": "resolved"}} in must_not
    # No positive filters were supplied, so there is no "must" clause.
    assert "must" not in body["query"]["bool"]


def test_get_alerts_combines_must_and_must_not():
    svc, client = _service()
    svc.get_alerts(severity="high", exclude_ioc=True, exclude_status=["resolved"])
    bool_q = client.search.call_args.kwargs["body"]["query"]["bool"]
    assert {"term": {"severity": "high"}} in bool_q["must"]
    assert {"term": {"rule_id": "ioc-detection"}} in bool_q["must_not"]
    assert {"term": {"status": "resolved"}} in bool_q["must_not"]


def test_get_alert_counts_sets_track_total_hits():
    svc, client = _service()
    client.search.return_value = {"hits": {"total": {"value": 0}}, "aggregations": {}}
    svc.get_alert_counts()
    body = client.search.call_args.kwargs["body"]
    assert body["track_total_hits"] is True


def test_get_alert_counts_exclude_status():
    svc, client = _service()
    client.search.return_value = {"hits": {"total": {"value": 0}}, "aggregations": {}}
    svc.get_alert_counts(exclude_status=["false_positive"])
    body = client.search.call_args.kwargs["body"]
    assert {"term": {"status": "false_positive"}} in body["query"]["bool"]["must_not"]


def test_get_ioc_stats_excludes_triaged():
    """IOC stats widget should count active matches only (no resolved / FP)."""
    svc, client = _service()
    client.search.return_value = {
        "hits": {"total": {"value": 0}},
        "aggregations": {
            "today_count": {"doc_count": 0},
            "by_threat_level": {"buckets": []},
            "by_ioc_type": {"buckets": []},
            "top_iocs": {"buckets": []},
        },
    }
    svc.get_ioc_stats()
    bool_q = client.search.call_args.kwargs["body"]["query"]["bool"]
    assert {"term": {"rule_id": "ioc-detection"}} in bool_q["must"]
    assert {"term": {"status": "resolved"}} in bool_q["must_not"]
    assert {"term": {"status": "false_positive"}} in bool_q["must_not"]
