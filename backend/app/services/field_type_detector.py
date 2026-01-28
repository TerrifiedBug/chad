"""Field type detection for smart field mapping validation.

Detects when Sigma fields map to OpenSearch text fields that should use .keyword sub-fields.
"""

import logging
from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


def detect_field_type(
    os_client: OpenSearch,
    index_pattern: str,
    field_path: str,
) -> dict:
    """
    Detect OpenSearch field type and recommend if .keyword suffix should be used.

    Args:
        os_client: OpenSearch client
        index_pattern: Index pattern (e.g., 'logs-*')
        field_path: Field path to check (e.g., 'process.executable')

    Returns:
        Dict with:
            - field_type: str ('text', 'keyword', 'ip', 'long', etc.)
            - has_keyword_subfield: bool
            - recommended_field: str (field_path with .keyword if needed)
            - reason: str (explanation of recommendation)
    """
    try:
        # Get field mapping from OpenSearch
        result = os_client.indices.get_field_mapping(
            index=index_pattern,
            fields=field_path,
        )

        # Extract mapping from first matching index
        for index_name, index_data in result.items():
            mappings = index_data.get("mappings", {})

            if field_path in mappings:
                field_mapping = mappings[field_path]["mapping"]
                field_info = list(field_mapping.values())[0]  # Get the actual field info

                field_type = field_info.get("type")
                has_keyword = "fields" in field_info and "keyword" in field_info["fields"]

                # Determine recommendation
                if field_type == "text" and has_keyword:
                    return {
                        "field_type": field_type,
                        "has_keyword_subfield": True,
                        "recommended_field": f"{field_path}.keyword",
                        "reason": f"Field '{field_path}' is type 'text' (analyzed). For wildcard/regex operators, use '{field_path}.keyword' for exact matching.",
                        "should_auto_correct": True,
                    }
                elif field_type == "keyword":
                    # Already a keyword field, no change needed
                    return {
                        "field_type": field_type,
                        "has_keyword_subfield": False,
                        "recommended_field": field_path,
                        "reason": f"Field '{field_path}' is already type 'keyword', no change needed.",
                        "should_auto_correct": False,
                    }
                else:
                    # Other field types (ip, long, boolean, etc.)
                    return {
                        "field_type": field_type,
                        "has_keyword_subfield": has_keyword,
                        "recommended_field": field_path,
                        "reason": f"Field '{field_path}' is type '{field_type}', no .keyword needed.",
                        "should_auto_correct": False,
                    }

        # Field not found in mappings
        return {
            "field_type": None,
            "has_keyword_subfield": False,
            "recommended_field": field_path,
            "reason": f"Field '{field_path}' not found in index '{index_pattern}'. Mapping may be to a non-existent field.",
            "should_auto_correct": False,
        }

    except Exception as e:
        # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
        logger.warning("Failed to detect field type for %r: %s", field_path, e)
        # On error, don't auto-correct - let user proceed
        return {
            "field_type": None,
            "has_keyword_subfield": False,
            "recommended_field": field_path,
            "reason": f"Could not determine field type: {str(e)}",
            "should_auto_correct": False,
        }


def auto_correct_field_mapping(
    os_client: OpenSearch,
    index_pattern: str,
    target_field: str,
) -> tuple[str, bool]:
    """
    Auto-correct a field mapping target if it points to a text field.

    Args:
        os_client: OpenSearch client
        index_pattern: Index pattern
        target_field: The field path to check/correct

    Returns:
        Tuple of (corrected_field, was_corrected)
    """
    detection = detect_field_type(os_client, index_pattern, target_field)

    if detection.get("should_auto_correct", False):
        logger.info(
            "Auto-correcting field mapping: %r -> %r",
            target_field, detection['recommended_field']
        )
        return detection["recommended_field"], True

    return target_field, False
