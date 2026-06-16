"""AlertService.update_status_by_query: filter→query + update_by_query call."""

from unittest.mock import MagicMock

from app.services.alerts import AlertService


def _service():
    client = MagicMock()
    client.update_by_query.return_value = {"updated": 42}
    return AlertService(client), client


def test_returns_updated_count():
    svc, client = _service()
    n = svc.update_status_by_query(status="false_positive", filter_status="new")
    assert n == 42
    client.update_by_query.assert_called_once()


def test_builds_filtered_query():
    svc, client = _service()
    svc.update_status_by_query(
        status="false_positive",
        filter_status="new",
        filter_severity="high",
        exclude_ioc=True,
    )
    body = client.update_by_query.call_args.kwargs["body"]
    must = body["query"]["bool"]["must"]
    must_not = body["query"]["bool"]["must_not"]
    assert {"term": {"status": "new"}} in must
    assert {"term": {"severity": "high"}} in must
    assert {"term": {"rule_id": "ioc-detection"}} in must_not
    # Script sets the new status.
    assert "ctx._source.status = params.s" in body["script"]["source"]
    assert body["script"]["params"]["s"] == "false_positive"


def test_exclude_status_goes_to_must_not():
    svc, client = _service()
    svc.update_status_by_query(
        status="acknowledged",
        exclude_status=["false_positive", "resolved"],
    )
    body = client.update_by_query.call_args.kwargs["body"]
    must_not = body["query"]["bool"]["must_not"]
    assert {"term": {"status": "false_positive"}} in must_not
    assert {"term": {"status": "resolved"}} in must_not
    assert "must" not in body["query"]["bool"]


def test_no_filters_matches_all():
    svc, client = _service()
    svc.update_status_by_query(status="resolved")
    body = client.update_by_query.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}


def test_acknowledged_sets_actor_fields():
    svc, client = _service()
    svc.update_status_by_query(status="acknowledged", user_id="admin@x.com")
    src = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
    assert "acknowledged_by" in src
    assert "conflicts" in client.update_by_query.call_args.kwargs
