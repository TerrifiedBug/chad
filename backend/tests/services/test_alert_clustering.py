"""Tests for alert clustering functionality."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services.alerts import cluster_alerts


class TestClusterAlertsDisabled:
    """Tests for cluster_alerts when clustering is disabled."""

    def test_disabled_returns_individual_clusters(self):
        alerts = [
            {"alert_id": "a1", "rule_id": "r1", "created_at": "2026-01-30T10:00:00Z"},
            {"alert_id": "a2", "rule_id": "r1", "created_at": "2026-01-30T10:01:00Z"},
        ]
        settings = {"enabled": False}

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 2
        assert clusters[0]["count"] == 1
        assert clusters[0]["alert_ids"] == ["a1"]
        assert clusters[1]["count"] == 1
        assert clusters[1]["alert_ids"] == ["a2"]

    def test_disabled_is_default(self):
        alerts = [
            {"alert_id": "a1", "rule_id": "r1", "created_at": "2026-01-30T10:00:00Z"},
        ]
        settings = {}  # No enabled key

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 1
        assert clusters[0]["count"] == 1


class TestClusterAlertsSameRule:
    """Tests for clustering alerts with the same rule."""

    def test_clusters_within_window(self):
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:30:00Z"
            },
            {
                "alert_id": "a3",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:45:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 1
        assert clusters[0]["count"] == 3
        assert set(clusters[0]["alert_ids"]) == {"a1", "a2", "a3"}

    def test_splits_clusters_outside_window(self):
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T12:00:00Z"  # 2 hours later
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 2
        assert clusters[0]["count"] == 1
        assert clusters[1]["count"] == 1

    def test_different_log_documents_same_rule_cluster_together(self):
        """Alerts with the same rule but different log contents should cluster."""
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server02"}},
                "created_at": "2026-01-30T10:05:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        # Same rule within time window should cluster regardless of log content
        assert len(clusters) == 1
        assert clusters[0]["count"] == 2
        assert set(clusters[0]["alert_ids"]) == {"a1", "a2"}


class TestClusterAlertsDifferentRules:
    """Tests for clustering alerts with different rules."""

    def test_different_rules_separate_clusters(self):
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
            {
                "alert_id": "a2",
                "rule_id": "r2",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:05:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 2


class TestClusterAlertsTimeRange:
    """Tests for time_range in clusters."""

    def test_time_range_set_correctly(self):
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:30:00Z"
            },
            {
                "alert_id": "a3",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:15:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 1
        first_ts, last_ts = clusters[0]["time_range"]
        assert first_ts == "2026-01-30T10:00:00Z"
        assert last_ts == "2026-01-30T10:30:00Z"


class TestClusterAlertsRepresentative:
    """Tests for representative alert selection."""

    def test_representative_is_first_by_time(self):
        alerts = [
            {
                "alert_id": "a3",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:30:00Z"
            },
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"  # Earliest
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:15:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 1
        # Representative should be the earliest alert (a1)
        assert clusters[0]["representative"]["alert_id"] == "a1"


class TestClusterAlertsEdgeCases:
    """Tests for edge cases in alert clustering."""

    def test_empty_alerts(self):
        settings = {"enabled": True, "window_minutes": 60}
        clusters = cluster_alerts([], settings)
        assert clusters == []

    def test_single_alert(self):
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 1
        assert clusters[0]["count"] == 1

    def test_missing_timestamp_handled(self):
        """Alerts with missing timestamps should still be handled."""
        alerts = [
            {
                "alert_id": "a1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
            },
            {
                "alert_id": "a2",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T10:00:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        # Should not raise an error
        clusters = cluster_alerts(alerts, settings)
        assert len(clusters) >= 1


class TestClusterAlertsSorting:
    """Tests for cluster sorting order."""

    def test_clusters_sorted_most_recent_first(self):
        alerts = [
            {
                "alert_id": "early1",
                "rule_id": "r1",
                "log_document": {"host": {"name": "server01"}},
                "created_at": "2026-01-30T08:00:00Z"
            },
            {
                "alert_id": "late1",
                "rule_id": "r2",
                "log_document": {"host": {"name": "server02"}},
                "created_at": "2026-01-30T12:00:00Z"
            },
        ]
        settings = {
            "enabled": True,
            "window_minutes": 60,
        }

        clusters = cluster_alerts(alerts, settings)

        assert len(clusters) == 2
        # The cluster with the later time should come first
        assert clusters[0]["representative"]["alert_id"] == "late1"
        assert clusters[1]["representative"]["alert_id"] == "early1"
