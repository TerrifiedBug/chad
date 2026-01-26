import logging
import time
from dataclasses import dataclass
from typing import Any

from opensearchpy import OpenSearch


logger = logging.getLogger(__name__)


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
    verify_certs: bool = True,
) -> OpenSearch:
    """Create an OpenSearch client with the given configuration.

    Args:
        host: OpenSearch host
        port: OpenSearch port
        username: Username for authentication (optional)
        password: Password for authentication (optional)
        use_ssl: Whether to use SSL/TLS
        verify_certs: Whether to verify SSL certificates (default: True for security)

    Returns:
        Configured OpenSearch client

    Security Note:
        In production, verify_certs should always be True to prevent Man-in-the-Middle attacks.
        Only set to False for development/testing with self-signed certificates.
    """
    auth = (username, password) if username and password else None

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=auth,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        ssl_show_warn=not verify_certs,  # Only show warnings if not verifying
        timeout=10,
    )


def validate_opensearch_connection(
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    use_ssl: bool,
    verify_certs: bool = True,
) -> ValidationResult:
    """
    Validate OpenSearch connection with full CHAD capability test.

    Args:
        host: OpenSearch host
        port: OpenSearch port
        username: Username for authentication (optional)
        password: Password for authentication (optional)
        use_ssl: Whether to use SSL/TLS
        verify_certs: Whether to verify SSL certificates (default: True for security)

    Steps:
    1. Connect to host (TCP connectivity)
    2. Authenticate (credentials valid)
    3. Create test index with percolator mapping
    4. Index a test query
    5. Run percolate query to verify matching works
    6. Clean up test artifacts

    Returns:
        ValidationResult with success status and detailed step results
    """
    steps: list[ValidationStep] = []
    client: OpenSearch | None = None
    test_index = f"chad-setup-test-{int(time.time())}"

    try:
        # Step 1: Connectivity
        try:
            client = create_client(host, port, username, password, use_ssl, verify_certs)
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
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup test index after query error: {cleanup_error}")
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
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup test index after percolate error: {cleanup_error}")
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
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup test index in finally block: {cleanup_error}")


def get_index_fields(client: OpenSearch, pattern: str) -> set[str]:
    """
    Get all field names from indices matching the pattern.

    Args:
        client: OpenSearch client
        pattern: Index pattern (e.g., "logs-*")

    Returns:
        Set of field names across all matching indices
    """
    fields: set[str] = set()

    try:
        # Get mapping for all indices matching pattern
        mappings = client.indices.get_mapping(index=pattern)

        for index_name, index_data in mappings.items():
            props = index_data.get("mappings", {}).get("properties", {})
            _extract_fields(props, "", fields)

    except Exception:
        # Pattern may not match any indices
        pass

    return fields


def _extract_fields(properties: dict[str, Any], prefix: str, fields: set[str]) -> None:
    """Recursively extract field names from mapping properties.

    Only includes searchable fields (text, keyword, etc.), not object containers.
    Object containers have 'properties' but no 'type' - they can't be searched directly.
    """
    for field_name, field_config in properties.items():
        full_name = f"{prefix}{field_name}" if prefix else field_name

        # Handle nested objects - recurse into them
        if "properties" in field_config:
            _extract_fields(field_config["properties"], f"{full_name}.", fields)
            # Only add the parent field if it also has a type (rare, but possible)
            if "type" in field_config:
                fields.add(full_name)
        else:
            # Regular field with a type - add it
            fields.add(full_name)


def validate_index_pattern(client: OpenSearch, pattern: str) -> dict[str, Any]:
    """
    Validate an index pattern exists and check permissions.

    Args:
        client: OpenSearch client
        pattern: Index pattern to validate

    Returns:
        Dict with validation result and index info
    """
    errors: list[str] = []

    try:
        # Get matching indices
        indices_info = client.cat.indices(index=pattern, format="json")
        indices = [idx["index"] for idx in indices_info]

        if not indices:
            return {
                "valid": False,
                "indices": [],
                "total_docs": 0,
                "sample_fields": [],
                "error": "No indices match this pattern",
            }

        # Get total doc count
        total_docs = sum(int(idx.get("docs.count", 0)) for idx in indices_info)

        # Test search permission
        try:
            client.search(index=pattern, body={"size": 0})
        except Exception as e:
            error_str = str(e).lower()
            if "403" in error_str or "security_exception" in error_str or "forbidden" in error_str:
                errors.append("Missing search permission for this index pattern")
            else:
                errors.append(f"Search test failed: {e}")

        # Test mapping permission
        try:
            client.indices.get_mapping(index=pattern)
        except Exception as e:
            error_str = str(e).lower()
            if "403" in error_str or "security_exception" in error_str or "forbidden" in error_str:
                errors.append("Missing get_mapping permission for this index pattern")
            else:
                errors.append(f"Mapping test failed: {e}")

        if errors:
            return {
                "valid": False,
                "indices": indices[:10],
                "total_docs": total_docs,
                "sample_fields": [],
                "error": "; ".join(errors),
            }

        # Get sample fields from mapping
        fields = get_index_fields(client, pattern)

        return {
            "valid": True,
            "indices": indices[:10],  # Limit to first 10
            "total_docs": total_docs,
            "sample_fields": sorted(list(fields))[:50],  # Limit to 50 fields
        }

    except Exception as e:
        return {
            "valid": False,
            "indices": [],
            "total_docs": 0,
            "sample_fields": [],
            "error": str(e),
        }
