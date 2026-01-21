import time
from dataclasses import dataclass
from typing import Any

from opensearchpy import OpenSearch


@dataclass
class ValidationStep:
    name: str
    success: bool
    error: str | None = None


@dataclass
class ValidationResult:
    success: bool
    steps: list[ValidationStep]


def create_client(
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    use_ssl: bool,
) -> OpenSearch:
    """Create an OpenSearch client with the given configuration."""
    auth = (username, password) if username and password else None

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=auth,
        use_ssl=use_ssl,
        verify_certs=False,  # For initial setup, may want to make configurable
        ssl_show_warn=False,
        timeout=10,
    )


def validate_opensearch_connection(
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    use_ssl: bool,
) -> ValidationResult:
    """
    Validate OpenSearch connection with full CHAD capability test.

    Steps:
    1. Connect to host (TCP connectivity)
    2. Authenticate (credentials valid)
    3. Create test index with percolator mapping
    4. Index a test query
    5. Run percolate query to verify matching works
    6. Clean up test artifacts
    """
    steps: list[ValidationStep] = []
    client: OpenSearch | None = None
    test_index = f"chad-setup-test-{int(time.time())}"

    try:
        # Step 1: Connectivity
        try:
            client = create_client(host, port, username, password, use_ssl)
            info = client.info()
            if not info:
                raise Exception("No response from OpenSearch")
            steps.append(ValidationStep(name="connectivity", success=True))
        except Exception as e:
            steps.append(ValidationStep(name="connectivity", success=False, error=str(e)))
            return ValidationResult(success=False, steps=steps)

        # Step 2: Authentication (implicitly tested by info(), but verify cluster health)
        try:
            health = client.cluster.health()
            if health.get("status") not in ("green", "yellow", "red"):
                raise Exception("Invalid cluster health response")
            steps.append(ValidationStep(name="authentication", success=True))
        except Exception as e:
            steps.append(ValidationStep(name="authentication", success=False, error=str(e)))
            return ValidationResult(success=False, steps=steps)

        # Step 3: Create test index with percolator mapping
        try:
            mapping = {
                "mappings": {
                    "properties": {
                        "query": {"type": "percolator"},
                        "message": {"type": "text"},
                    }
                }
            }
            client.indices.create(index=test_index, body=mapping)
            steps.append(ValidationStep(name="create_index", success=True))
        except Exception as e:
            steps.append(ValidationStep(name="create_index", success=False, error=str(e)))
            return ValidationResult(success=False, steps=steps)

        # Step 4: Index a test query
        try:
            test_query = {
                "query": {
                    "match_all": {}
                }
            }
            client.index(index=test_index, id="test-query", body=test_query, refresh=True)
            steps.append(ValidationStep(name="index_query", success=True))
        except Exception as e:
            steps.append(ValidationStep(name="index_query", success=False, error=str(e)))
            # Try to clean up before returning
            try:
                client.indices.delete(index=test_index)
            except:
                pass
            return ValidationResult(success=False, steps=steps)

        # Step 5: Run percolate query
        try:
            percolate_query = {
                "query": {
                    "percolate": {
                        "field": "query",
                        "document": {
                            "message": "test document"
                        }
                    }
                }
            }
            result = client.search(index=test_index, body=percolate_query)
            hits = result.get("hits", {}).get("total", {}).get("value", 0)
            if hits < 1:
                raise Exception("Percolate query returned no matches (expected 1)")
            steps.append(ValidationStep(name="percolate", success=True))
        except Exception as e:
            steps.append(ValidationStep(name="percolate", success=False, error=str(e)))
            # Try to clean up before returning
            try:
                client.indices.delete(index=test_index)
            except:
                pass
            return ValidationResult(success=False, steps=steps)

        # Step 6: Cleanup
        try:
            client.indices.delete(index=test_index)
            steps.append(ValidationStep(name="cleanup", success=True))
        except Exception as e:
            # Cleanup failure is non-fatal but we report it
            steps.append(ValidationStep(name="cleanup", success=False, error=str(e)))

        return ValidationResult(success=True, steps=steps)

    except Exception as e:
        # Unexpected error
        steps.append(ValidationStep(name="unexpected", success=False, error=str(e)))
        return ValidationResult(success=False, steps=steps)

    finally:
        # Ensure test index is deleted even on unexpected errors
        if client:
            try:
                client.indices.delete(index=test_index, ignore=[404])
            except:
                pass
