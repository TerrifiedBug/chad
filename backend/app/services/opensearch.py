import logging
import ssl
import time
import warnings
from dataclasses import dataclass
from typing import Any

from opensearchpy import OpenSearch


logger = logging.getLogger(__name__)

# Suppress urllib3 InsecureRequestWarning when verify_certs=False
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Track whether SSL warning has been logged to avoid repeated warnings
_ssl_warning_logged = False


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
    global _ssl_warning_logged
    auth = (username, password) if username and password else None

    # When verify_certs is False, we need to provide an ssl_context that explicitly
    # disables certificate verification. This is required for opensearch-py to properly
    # disable SSL verification in all cases (e.g., self-signed certificates).
    ssl_context = None
    if use_ssl and not verify_certs:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Only log once per process lifetime
        if not _ssl_warning_logged:
            logger.warning("[SECURITY] SSL certificate verification is DISABLED. This should only be used in development environments!")
            _ssl_warning_logged = True

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=auth,
        use_ssl=use_ssl,
        ssl_context=ssl_context,
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

        # Step 2.5: SSL Verification Status (informational step)
        if use_ssl:
            ssl_status = "enabled" if verify_certs else "disabled (development mode)"
            steps.append(ValidationStep(
                name="ssl_verification",
                success=True,
                error=f"SSL verification: {ssl_status}"
            ))
        else:
            steps.append(ValidationStep(
                name="ssl_verification",
                success=True,
                error="SSL not enabled (plain text connection)"
            ))

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


def get_index_fields(
    client: OpenSearch,
    pattern: str,
    include_multi_fields: bool = True,
) -> set[str]:
    """
    Get all field names from indices matching the pattern.

    Args:
        client: OpenSearch client
        pattern: Index pattern (e.g., "logs-*")
        include_multi_fields: If True, include multi-fields like .keyword sub-fields.
                              If False, only return base fields (better for UI dropdowns).

    Returns:
        Set of field names across all matching indices
    """
    fields: set[str] = set()

    try:
        # Get mapping for all indices matching pattern
        mappings = client.indices.get_mapping(index=pattern)

        for index_name, index_data in mappings.items():
            props = index_data.get("mappings", {}).get("properties", {})
            _extract_fields(props, "", fields, include_multi_fields)

    except Exception:
        # Pattern may not match any indices
        pass

    return fields


def find_similar_fields(target_field: str, available_fields: list[str] | set[str]) -> list[str]:
    """Find fields similar to target_field using fuzzy matching.

    Args:
        target_field: Field name to find matches for
        available_fields: List/set of available field names

    Returns:
        List of similar field names (max 5)
    """
    from difflib import get_close_matches

    similar = list(get_close_matches(target_field, available_fields, n=5, cutoff=0.6))

    # Also check for component matching in nested fields
    if '.' in target_field:
        components = target_field.split('.')
        for field in available_fields:
            if isinstance(field, str) and '.' in field:
                field_components = field.split('.')
                # Check if any component matches
                for comp in components:
                    if comp in field_components and field not in similar:
                        similar.append(field)
                        if len(similar) >= 5:
                            return similar

    return similar


def _extract_fields(
    properties: dict[str, Any],
    prefix: str,
    fields: set[str],
    include_multi_fields: bool = True,
) -> None:
    """Recursively extract field names from mapping properties.

    Only includes searchable fields (text, keyword, etc.), not object containers.
    Object containers have 'properties' but no 'type' - they can't be searched directly.

    Args:
        properties: Field mappings from OpenSearch
        prefix: Current field path (for recursion)
        fields: Set to populate with field names
        include_multi_fields: If True, extract multi-fields like .keyword.
                              If False, skip the 'fields' sub-object.
    """
    for field_name, field_config in properties.items():
        full_name = f"{prefix}{field_name}" if prefix else field_name

        # Handle nested objects - recurse into them
        if "properties" in field_config:
            _extract_fields(field_config["properties"], f"{full_name}.", fields, include_multi_fields)
            # Only add the parent field if it also has a type (rare, but possible)
            if "type" in field_config:
                fields.add(full_name)
        else:
            # Regular field with a type - add it
            fields.add(full_name)

            # Extract multi-fields (e.g., .keyword sub-fields) if requested
            # OpenSearch multi-fields structure: {"type": "text", "fields": {"keyword": {"type": "keyword"}}}
            if include_multi_fields and "fields" in field_config:
                for sub_field_name, sub_field_config in field_config["fields"].items():
                    sub_full_name = f"{full_name}.{sub_field_name}"
                    fields.add(sub_full_name)
                    # Recurse if sub-field also has nested properties
                    if "properties" in sub_field_config:
                        _extract_fields(sub_field_config["properties"], f"{sub_full_name}.", fields, include_multi_fields)


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
