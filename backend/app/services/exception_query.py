"""Translate exception clauses into OpenSearch query fragments.

The fragment returned here is placed inside an OpenSearch ``bool.must_not`` list
by the historical-test preview, so it must select exactly the events that
:func:`app.services.alerts.check_exception_match` returns ``True`` for. ``NOT_*``
operators therefore invert (a ``must_not`` of a ``must_not`` is a ``must``).
"""

import json
from typing import Any

from app.models.rule_exception import ExceptionOperator


def exception_clause_to_os_filter(
    field: str,
    operator: ExceptionOperator,
    value: str,
) -> dict[str, Any]:
    """Return the OpenSearch query fragment matching this exception condition.

    Mirrors :func:`app.services.alerts.check_exception_match` semantics so the
    preview count and runtime suppression agree.
    """
    if operator == ExceptionOperator.EQUALS:
        return {"match_phrase": {field: value}}
    if operator == ExceptionOperator.CONTAINS:
        return {"wildcard": {field: f"*{value}*"}}
    if operator == ExceptionOperator.STARTS_WITH:
        return {"prefix": {field: value}}
    if operator == ExceptionOperator.ENDS_WITH:
        return {"wildcard": {field: f"*{value}"}}
    if operator == ExceptionOperator.REGEX:
        return {"regexp": {field: value}}
    if operator == ExceptionOperator.IN_LIST:
        try:
            parsed = json.loads(value)
            values = parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, ValueError):
            values = []
        return {"terms": {field: values}}
    if operator == ExceptionOperator.NOT_EQUALS:
        return {"bool": {"must_not": [{"match_phrase": {field: value}}]}}
    if operator == ExceptionOperator.NOT_CONTAINS:
        return {"bool": {"must_not": [{"wildcard": {field: f"*{value}*"}}]}}
    # Defensive fallback: an unknown operator matches nothing (no suppression).
    return {"bool": {"must_not": [{"match_all": {}}]}}
