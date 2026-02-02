"""Tests for alert service exception matching."""


from app.models.rule_exception import ExceptionOperator
from app.services.alerts import (
    check_exception_match,
    get_nested_value,
    should_suppress_alert,
)


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
        log = {"host": {"name": "DC01"}}
        exceptions = [
            {"field": "user.name", "operator": "equals", "value": "svc_backup", "is_active": True},
            {"field": "host.name", "operator": "in_list", "value": '["DC01", "DC02"]', "is_active": True},
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
