"""Tests for alert service exception matching."""


from unittest.mock import MagicMock

from app.models.rule_exception import ExceptionOperator
from app.services.alerts import (
    AlertService,
    check_exception_match,
    get_nested_value,
    should_suppress_alert,
)


class TestBulkCreateAlerts:
    """Tests for AlertService.bulk_create_alerts."""

    def test_empty_returns_no_ids_and_no_call(self):
        client = MagicMock()
        assert AlertService(client).bulk_create_alerts("idx", []) == []
        client.bulk.assert_not_called()

    def test_single_bulk_call_returns_ids(self):
        client = MagicMock()
        client.bulk.return_value = {"errors": False}
        alerts = [
            {"rule_id": "r1", "rule_title": "T1", "severity": "high", "log_document": {"a": 1}},
            {"rule_id": "r2", "rule_title": "T2", "severity": "low", "log_document": {"b": 2}},
        ]
        ids = AlertService(client).bulk_create_alerts("chad-alerts-x", alerts, ensure_index=False)

        assert len(ids) == 2
        client.bulk.assert_called_once()
        # ensure_index=False must skip the index existence round trip.
        client.indices.exists.assert_not_called()

    def test_ti_enrichment_lifted_to_top_level(self):
        client = MagicMock()
        client.bulk.return_value = {"errors": False}
        alerts = [{
            "rule_id": "r1", "rule_title": "T1", "severity": "high",
            "log_document": {"a": 1, "ti_enrichment": {"indicators": ["x"]}},
        }]
        AlertService(client).bulk_create_alerts("idx", alerts, ensure_index=False)

        _, kwargs = client.bulk.call_args
        body = kwargs.get("body") or client.bulk.call_args[0][0]
        # body = [action, doc]; doc carries ti_enrichment at top level, not in log_document
        doc = body[1]
        assert doc["ti_enrichment"] == {"indicators": ["x"]}
        assert "ti_enrichment" not in doc["log_document"]


class TestGetNestedValue:
    """Tests for get_nested_value helper function."""

    def test_simple_key(self):
        log = {"user": "admin"}
        assert get_nested_value(log, "user") == "admin"

    def test_nested_key(self):
        log = {"process": {"name": "backup.exe"}}
        assert get_nested_value(log, "process.name") == "backup.exe"

    def test_deeply_nested(self):
        log = {"level1": {"level2": {"level3": "value"}}}
        assert get_nested_value(log, "level1.level2.level3") == "value"

    def test_missing_key(self):
        log = {"user": "admin"}
        assert get_nested_value(log, "missing") is None

    def test_missing_nested_key(self):
        log = {"process": {"name": "backup.exe"}}
        assert get_nested_value(log, "process.missing") is None

    def test_partially_missing_path(self):
        log = {"user": "admin"}
        assert get_nested_value(log, "user.name") is None


class TestExceptionMatching:
    """Tests for check_exception_match function."""

    def test_equals_matches(self):
        log = {"user": {"name": "svc_backup"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.EQUALS, "svc_backup")
            is True
        )

    def test_equals_no_match(self):
        log = {"user": {"name": "admin"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.EQUALS, "svc_backup")
            is False
        )

    def test_not_equals_matches(self):
        log = {"user": {"name": "admin"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.NOT_EQUALS, "svc_backup")
            is True
        )

    def test_not_equals_no_match(self):
        log = {"user": {"name": "svc_backup"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.NOT_EQUALS, "svc_backup")
            is False
        )

    def test_contains_matches(self):
        log = {"process": {"command_line": "backup.exe --silent"}}
        assert (
            check_exception_match(
                log, "process.command_line", ExceptionOperator.CONTAINS, "backup"
            )
            is True
        )

    def test_contains_no_match(self):
        log = {"process": {"command_line": "malware.exe --run"}}
        assert (
            check_exception_match(
                log, "process.command_line", ExceptionOperator.CONTAINS, "backup"
            )
            is False
        )

    def test_not_contains_matches(self):
        log = {"process": {"command_line": "malware.exe --run"}}
        assert (
            check_exception_match(
                log, "process.command_line", ExceptionOperator.NOT_CONTAINS, "backup"
            )
            is True
        )

    def test_not_contains_no_match(self):
        log = {"process": {"command_line": "backup.exe --silent"}}
        assert (
            check_exception_match(
                log, "process.command_line", ExceptionOperator.NOT_CONTAINS, "backup"
            )
            is False
        )

    def test_starts_with_matches(self):
        log = {"user": {"name": "svc_backup_prod"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.STARTS_WITH, "svc_")
            is True
        )

    def test_starts_with_no_match(self):
        log = {"user": {"name": "admin_user"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.STARTS_WITH, "svc_")
            is False
        )

    def test_ends_with_matches(self):
        log = {"host": {"name": "server-prod"}}
        assert (
            check_exception_match(log, "host.name", ExceptionOperator.ENDS_WITH, "-prod")
            is True
        )

    def test_ends_with_no_match(self):
        log = {"host": {"name": "server-dev"}}
        assert (
            check_exception_match(log, "host.name", ExceptionOperator.ENDS_WITH, "-prod")
            is False
        )

    def test_regex_matches(self):
        log = {"user": {"name": "svc_backup_prod"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.REGEX, r"^svc_.*")
            is True
        )

    def test_regex_no_match(self):
        log = {"user": {"name": "admin_user"}}
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.REGEX, r"^svc_.*")
            is False
        )

    def test_regex_invalid_pattern(self):
        log = {"user": {"name": "test"}}
        # Invalid regex should return False, not raise exception
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.REGEX, r"[invalid")
            is False
        )

    def test_regex_catastrophic_backtracking_times_out(self):
        # A classic ReDoS pattern against an adversarial non-matching string would
        # hang the stdlib `re` engine. The timeout-bounded matcher must return
        # quickly and fail closed (no suppression) instead of pegging the worker.
        import time

        log = {"user": {"name": "a" * 64 + "!"}}
        start = time.monotonic()
        result = check_exception_match(
            log, "user.name", ExceptionOperator.REGEX, r"(a+)+$"
        )
        elapsed = time.monotonic() - start

        assert result is False
        # Bounded by the regex timeout (1s) plus slack; nowhere near the minutes
        # the stdlib engine would take on this input.
        assert elapsed < 5.0

    def test_in_list_matches(self):
        log = {"host": {"name": "DC01"}}
        assert (
            check_exception_match(
                log, "host.name", ExceptionOperator.IN_LIST, '["DC01", "DC02"]'
            )
            is True
        )

    def test_in_list_no_match(self):
        log = {"host": {"name": "WEB01"}}
        assert (
            check_exception_match(
                log, "host.name", ExceptionOperator.IN_LIST, '["DC01", "DC02"]'
            )
            is False
        )

    def test_in_list_invalid_json(self):
        log = {"host": {"name": "DC01"}}
        # Invalid JSON should return False, not raise exception
        assert (
            check_exception_match(log, "host.name", ExceptionOperator.IN_LIST, "not json")
            is False
        )

    def test_nested_field(self):
        log = {"process": {"name": "backup.exe"}}
        assert (
            check_exception_match(log, "process.name", ExceptionOperator.EQUALS, "backup.exe")
            is True
        )

    def test_missing_field_returns_false(self):
        log = {"user": {"name": "admin"}}
        assert (
            check_exception_match(log, "nonexistent", ExceptionOperator.EQUALS, "value")
            is False
        )

    def test_numeric_value_converted_to_string(self):
        log = {"port": 443}
        assert check_exception_match(log, "port", ExceptionOperator.EQUALS, "443") is True

    def test_flat_key_with_dot(self):
        """Test that literal keys with dots are also supported."""
        # If a key literally contains a dot (e.g., from ECS logs)
        log = {"user.name": "svc_backup"}
        # This should NOT match because get_nested_value looks for nested structure
        assert (
            check_exception_match(log, "user.name", ExceptionOperator.EQUALS, "svc_backup")
            is False
        )


class TestShouldSuppressAlert:
    """Tests for should_suppress_alert function."""

    def test_matching_exception_suppresses(self):
        log = {"user": {"name": "svc_backup"}}
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup", "is_active": True}
        ]
        assert should_suppress_alert(log, exceptions) is True

    def test_no_matching_exception_does_not_suppress(self):
        log = {"user": {"name": "admin"}}
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup", "is_active": True}
        ]
        assert should_suppress_alert(log, exceptions) is False

    def test_inactive_exception_ignored(self):
        log = {"user": {"name": "svc_backup"}}
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup", "is_active": False}
        ]
        assert should_suppress_alert(log, exceptions) is False

    def test_multiple_exceptions_any_match_suppresses(self):
        """Test that exceptions in different groups are ORed - any match suppresses."""
        log = {"host": {"name": "DC01"}}
        # Different group_ids means OR logic - any group match suppresses
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup", "is_active": True, "group_id": "group1"},
            {"field": "host.name", "operator": "in_list", "value": '["DC01", "DC02"]', "is_active": True, "group_id": "group2"},
        ]
        assert should_suppress_alert(log, exceptions) is True

    def test_empty_exceptions_does_not_suppress(self):
        log = {"user": {"name": "admin"}}
        exceptions = []
        assert should_suppress_alert(log, exceptions) is False

    def test_default_is_active_true(self):
        """If is_active is not provided, default to True."""
        log = {"user": {"name": "svc_backup"}}
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup"}
        ]
        assert should_suppress_alert(log, exceptions) is True
