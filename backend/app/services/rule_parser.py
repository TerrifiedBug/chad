"""
Sigma rule YAML parsing utilities.

Extracts fields and other metadata from Sigma rule YAML content.
"""

import yaml


def extract_sigma_fields(yaml_content: str) -> list[str]:
    """
    Extract all field names used in a Sigma rule's detection section.

    Args:
        yaml_content: The YAML content of a Sigma rule

    Returns:
        List of unique field names used in the detection logic
    """
    try:
        rule = yaml.safe_load(yaml_content)
    except yaml.YAMLError:
        return []

    if not rule or not isinstance(rule, dict):
        return []

    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return []

    fields: set[str] = set()

    def extract_from_dict(d: dict) -> None:
        """Recursively extract field names from a detection dict."""
        for key, value in d.items():
            # Skip the 'condition' key and internal keys
            if key in ("condition", "timeframe"):
                continue

            # If this is a selection dict, extract field names
            if isinstance(value, dict):
                for field_key in value.keys():
                    # Field names may have modifiers like |contains, |endswith
                    base_field = field_key.split("|")[0]
                    if base_field:
                        fields.add(base_field)
            elif isinstance(value, list):
                # Could be a list of dicts (OR conditions)
                for item in value:
                    if isinstance(item, dict):
                        for field_key in item.keys():
                            base_field = field_key.split("|")[0]
                            if base_field:
                                fields.add(base_field)

    # Process each selection in detection
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            extract_from_dict({key: value})
        elif isinstance(value, list):
            extract_from_dict({key: value})

    return sorted(fields)
