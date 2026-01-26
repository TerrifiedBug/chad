"""Integration tests for OpenSearch connectivity."""

import pytest
from opensearchpy import OpenSearch

from app.services.opensearch import validate_opensearch_connection


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opensearch_validation_with_real_client():
    """Test OpenSearch validation with actual connection.

    Note: This test requires a running OpenSearch instance.
    Skip with: pytest -m "not integration"
    """
    # These should match your test environment
    result = validate_opensearch_connection(
        host="localhost",
        port=9200,
        username=None,
        password=None,
        use_ssl=False,
    )

    # The test should pass if OpenSearch is accessible
    # Check that all steps completed
    assert result.success is True
    assert len(result.steps) == 6  # All validation steps

    # Verify each step succeeded
    for step in result.steps:
        assert step.success, f"Step {step.name} failed: {step.error}"


@pytest.mark.asyncio
async def test_opensearch_client_creation():
    """Test OpenSearch client creation without connecting."""
    from app.services.opensearch import create_client

    # Create client (doesn't connect yet)
    client = create_client(
        host="localhost",
        port=9200,
        username="admin",
        password="admin",
        use_ssl=False,
    )

    assert client is not None
    assert client.cluster == "localhost:9200"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opensearch_percolator_query():
    """Test OpenSearch percolator query functionality.

    Note: This requires a running OpenSearch with percolator support.
    """
    import time

    client = OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )

    test_index = f"chad-test-{int(time.time())}"

    try:
        # Create test index with percolator mapping
        mapping = {
            "mappings": {
                "properties": {
                    "query": {"type": "percolator"},
                    "message": {"type": "text"},
                }
            }
        }

        client.indices.create(index=test_index, body=mapping)

        # Index a percolator query
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"message": "test"}},
                    ]
                }
            }
        }

        client.index(index=test_index, body={"query": query})

        # Test percolate query
        doc = {"message": "this is a test"}

        response = client.search(
            index=test_index,
            body={
                "query": {
                    "percolate": {
                        "field": "query",
                        "document": doc
                    }
                }
            }
        )

        # Verify the query matched
        assert response["hits"]["total"]["value"] == 1

    finally:
        # Cleanup
        try:
            client.indices.delete(index=test_index)
        except Exception:
            pass
