"""Integration tests for OpenSearch connectivity."""

import os
from urllib.parse import urlparse

import pytest
from opensearchpy import OpenSearch

from app.services.opensearch import validate_opensearch_connection


def get_opensearch_config():
    """Get OpenSearch config from environment variables."""
    host_url = os.getenv("OPENSEARCH_HOST", "http://localhost:9200")
    parsed = urlparse(host_url)

    return {
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 9200,
        "use_ssl": parsed.scheme == "https",
        "verify_certs": False,  # Allow self-signed certs in test environments
        "username": os.getenv("OPENSEARCH_USER"),
        "password": os.getenv("OPENSEARCH_PASSWORD"),
    }


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opensearch_validation_with_real_client():
    """Test OpenSearch validation with actual connection.

    Note: This test requires a running OpenSearch instance.
    Skip with: pytest -m "not integration"
    """
    config = get_opensearch_config()
    result = validate_opensearch_connection(
        host=config["host"],
        port=config["port"],
        username=config["username"],
        password=config["password"],
        use_ssl=config["use_ssl"],
        verify_certs=config["verify_certs"],
    )

    # The test should pass if OpenSearch is accessible
    # Check that all steps completed
    assert result.success is True
    assert len(result.steps) == 7  # All validation steps including cleanup

    # Verify each step succeeded
    for step in result.steps:
        assert step.success, f"Step {step.name} failed: {step.error}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opensearch_client_creation():
    """Test OpenSearch client creation and connection."""
    from app.services.opensearch import create_client

    config = get_opensearch_config()
    client = create_client(
        host=config["host"],
        port=config["port"],
        username=config["username"],
        password=config["password"],
        use_ssl=config["use_ssl"],
        verify_certs=config["verify_certs"],
    )

    assert client is not None
    # Verify we can actually connect
    info = client.info()
    assert "cluster_name" in info


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opensearch_percolator_query():
    """Test OpenSearch percolator query functionality.

    Note: This requires a running OpenSearch with percolator support.
    """
    import time

    config = get_opensearch_config()
    client = OpenSearch(
        hosts=[{"host": config["host"], "port": config["port"]}],
        http_auth=(config["username"], config["password"]) if config["username"] else None,
        use_ssl=config["use_ssl"],
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

        # Index a percolator query - the document must have a "query" field at the top level
        percolator_doc = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"message": "test"}},
                    ]
                }
            }
        }

        client.index(index=test_index, body=percolator_doc, refresh=True)

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
