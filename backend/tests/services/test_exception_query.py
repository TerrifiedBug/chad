"""Unit tests for exception_clause_to_os_filter.

The returned fragment goes into an OpenSearch bool.must_not, so it must select
the same events that alerts.check_exception_match returns True for.
"""

from app.models.rule_exception import ExceptionOperator
from app.services.exception_query import exception_clause_to_os_filter


def test_equals_uses_match_phrase():
    assert exception_clause_to_os_filter(
        "user.name", ExceptionOperator.EQUALS, "svc_backup"
    ) == {"match_phrase": {"user.name": "svc_backup"}}


def test_contains_uses_wildcard():
    assert exception_clause_to_os_filter(
        "process.command_line", ExceptionOperator.CONTAINS, "update"
    ) == {"wildcard": {"process.command_line": "*update*"}}


def test_starts_with_uses_prefix():
    assert exception_clause_to_os_filter(
        "host.name", ExceptionOperator.STARTS_WITH, "prod-"
    ) == {"prefix": {"host.name": "prod-"}}


def test_ends_with_uses_suffix_wildcard():
    assert exception_clause_to_os_filter(
        "host.name", ExceptionOperator.ENDS_WITH, ".internal"
    ) == {"wildcard": {"host.name": "*.internal"}}


def test_regex_uses_regexp():
    assert exception_clause_to_os_filter(
        "url", ExceptionOperator.REGEX, "foo.*bar"
    ) == {"regexp": {"url": "foo.*bar"}}


def test_in_list_parses_json_array():
    assert exception_clause_to_os_filter(
        "user.name", ExceptionOperator.IN_LIST, '["a", "b"]'
    ) == {"terms": {"user.name": ["a", "b"]}}


def test_in_list_bad_json_is_empty_terms():
    assert exception_clause_to_os_filter(
        "user.name", ExceptionOperator.IN_LIST, "not-json"
    ) == {"terms": {"user.name": []}}


def test_not_equals_wraps_in_must_not():
    assert exception_clause_to_os_filter(
        "user.name", ExceptionOperator.NOT_EQUALS, "svc_backup"
    ) == {"bool": {"must_not": [{"match_phrase": {"user.name": "svc_backup"}}]}}


def test_not_contains_wraps_wildcard_in_must_not():
    assert exception_clause_to_os_filter(
        "cmd", ExceptionOperator.NOT_CONTAINS, "update"
    ) == {"bool": {"must_not": [{"wildcard": {"cmd": "*update*"}}]}}
