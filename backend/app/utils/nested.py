"""Dotted-path helpers for nested dicts."""

from typing import Any


def get_nested_value(obj: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation (None if absent)."""
    value = obj
    for key in path.split("."):
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def set_nested_value(doc: dict, path: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation, creating parents."""
    keys = path.split(".")
    current = doc
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
