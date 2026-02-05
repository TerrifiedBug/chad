from app.core.exceptions import OpenSearchUnavailableError


def test_opensearch_unavailable_error_message():
    err = OpenSearchUnavailableError("Connection refused")
    assert str(err) == "OpenSearch unavailable: Connection refused"
    assert err.reason == "Connection refused"


def test_opensearch_unavailable_error_default():
    err = OpenSearchUnavailableError()
    assert "OpenSearch unavailable" in str(err)
