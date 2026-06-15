"""Unit tests for the SLA policy + due-time computation."""

from datetime import UTC, datetime, timedelta

from app.services.sla import (
    DEFAULT_SLA_POLICY,
    compute_due_at,
    merge_policy,
)


def test_merge_policy_defaults_when_empty():
    policy = merge_policy(None)
    assert policy["enabled"] is False
    assert policy["targets_minutes"]["critical"] == 60
    assert set(policy["targets_minutes"]) == set(DEFAULT_SLA_POLICY["targets_minutes"])


def test_merge_policy_overlays_partial():
    policy = merge_policy({"enabled": True, "targets_minutes": {"critical": 30}})
    assert policy["enabled"] is True
    assert policy["targets_minutes"]["critical"] == 30
    # untouched severities keep defaults
    assert policy["targets_minutes"]["high"] == 240


def test_merge_policy_ignores_malformed_target():
    policy = merge_policy({"targets_minutes": {"critical": "not-a-number"}})
    assert policy["targets_minutes"]["critical"] == 60  # default retained


def test_compute_due_at_disabled_returns_none():
    created = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)
    policy = {"enabled": False, "targets_minutes": {"high": 240}}
    assert compute_due_at(created, "high", policy) is None


def test_compute_due_at_zero_target_returns_none():
    created = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)
    policy = {"enabled": True, "targets_minutes": {"informational": 0}}
    assert compute_due_at(created, "informational", policy) is None


def test_compute_due_at_adds_target():
    created = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)
    policy = {"enabled": True, "targets_minutes": {"high": 240}}
    due = compute_due_at(created, "high", policy)
    assert due == created + timedelta(minutes=240)


def test_compute_due_at_accepts_iso_string_and_is_case_insensitive():
    policy = {"enabled": True, "targets_minutes": {"critical": 60}}
    due = compute_due_at("2026-06-14T12:00:00+00:00", "CRITICAL", policy)
    assert due == datetime(2026, 6, 14, 13, 0, tzinfo=UTC)


def test_compute_due_at_unparseable_created_returns_none():
    policy = {"enabled": True, "targets_minutes": {"high": 240}}
    assert compute_due_at("not-a-date", "high", policy) is None
