"""Tests for bulk alert writing."""

import pytest
from unittest.mock import MagicMock


class TestBulkAlertWriter:
    """Tests for bulk alert creation."""

    def test_bulk_create_alerts_single_call(self):
        """bulk_create_alerts should make one OpenSearch bulk call."""
        from app.services.alerts import AlertService

        mock_client = MagicMock()
        mock_client.indices.exists.return_value = True
        mock_client.bulk.return_value = {"errors": False, "items": []}

        service = AlertService(mock_client)

        alerts = [
            {"rule_id": "1", "rule_title": "Test 1", "severity": "high", "log_document": {}},
            {"rule_id": "2", "rule_title": "Test 2", "severity": "medium", "log_document": {}},
        ]

        service.bulk_create_alerts("chad-alerts-test", alerts)

        # Should make exactly ONE bulk call
        assert mock_client.bulk.call_count == 1

    def test_bulk_create_alerts_empty_list(self):
        """Empty alerts list should not call bulk."""
        from app.services.alerts import AlertService

        mock_client = MagicMock()

        service = AlertService(mock_client)
        service.bulk_create_alerts("index", [])

        mock_client.bulk.assert_not_called()

    def test_bulk_create_alerts_returns_ids(self):
        """bulk_create_alerts should return list of alert IDs."""
        from app.services.alerts import AlertService

        mock_client = MagicMock()
        mock_client.indices.exists.return_value = True
        mock_client.bulk.return_value = {"errors": False, "items": []}

        service = AlertService(mock_client)

        alerts = [
            {"rule_id": "1", "rule_title": "Test", "severity": "high", "log_document": {"@timestamp": "2026-01-30T00:00:00Z"}},
        ]

        result = service.bulk_create_alerts("chad-alerts-test", alerts)

        assert len(result) == 1
        assert isinstance(result[0], str)
