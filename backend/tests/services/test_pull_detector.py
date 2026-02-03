"""Tests for PullDetector service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.pull_detector import PullDetector


class TestPullDetectorInit:
    def test_pull_detector_creation(self):
        """PullDetector should initialize with OpenSearch client."""
        mock_client = MagicMock()
        detector = PullDetector(client=mock_client)
        assert detector.client == mock_client


class TestPullDetectorBuildQuery:
    def test_build_time_filtered_query(self):
        """Should build DSL query with time filter."""
        mock_client = MagicMock()
        detector = PullDetector(client=mock_client)

        base_query = {"bool": {"must": [{"match": {"event.code": "1"}}]}}
        last_poll = datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC)
        now = datetime(2026, 2, 1, 10, 5, 0, tzinfo=UTC)

        result = detector.build_time_filtered_query(base_query, last_poll, now)

        # Should wrap original query and add time filter
        assert "bool" in result
        assert "must" in result["bool"]
        # Should have range filter on @timestamp
        range_filter = None
        for clause in result["bool"]["must"]:
            if "range" in clause:
                range_filter = clause["range"]
                break
        assert range_filter is not None
        assert "@timestamp" in range_filter

    def test_build_time_filtered_query_no_last_poll(self):
        """Should handle case when no previous poll exists."""
        mock_client = MagicMock()
        detector = PullDetector(client=mock_client)

        base_query = {"bool": {"must": [{"match": {"event.code": "1"}}]}}
        now = datetime(2026, 2, 1, 10, 5, 0, tzinfo=UTC)

        # When last_poll is None, should default to 1 hour lookback
        result = detector.build_time_filtered_query(base_query, None, now)
        assert "bool" in result


class TestPollIndexPattern:
    @pytest.fixture
    def mock_db(self):
        """Mock async database session."""
        db = AsyncMock()
        # Mock execute to return empty results for field mappings and exceptions
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=mock_result)
        return db

    @pytest.fixture
    def mock_sigma_service(self):
        """Mock SigmaService with successful translation."""
        service = MagicMock()
        # Mock translate_and_validate to return a valid result
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.query = {"query": {"query_string": {"query": "event.code:1"}}}
        mock_result.fields = set()
        mock_result.errors = None
        service.translate_and_validate = MagicMock(return_value=mock_result)
        return service

    @pytest.fixture
    def mock_alert_service(self):
        """Mock AlertService - NOTE: create_alert is SYNC, not async."""
        service = MagicMock()
        # create_alert is a SYNC method that returns a dict
        service.create_alert = MagicMock(return_value={
            "alert_id": "test-alert-123",
            "rule_id": "test-rule",
            "rule_title": "Test Rule",
            "severity": "high",
            "tags": [],
            "status": "new",
            "log_document": {},
            "created_at": datetime.now(UTC).isoformat(),
        })
        return service

    @pytest.mark.asyncio
    async def test_poll_index_pattern_creates_alerts_for_matches(
        self, mock_db, mock_sigma_service, mock_alert_service
    ):
        """Should create alerts for documents matching deployed rules."""
        mock_client = MagicMock()
        # Mock search to return hits with sort values for pagination
        mock_client.search = MagicMock(
            return_value={
                "hits": {
                    "total": {"value": 2, "relation": "eq"},
                    "hits": [
                        {"_id": "doc1", "_source": {"message": "suspicious"}, "sort": [1, "doc1"]},
                        {"_id": "doc2", "_source": {"message": "malware"}, "sort": [2, "doc2"]},
                    ]
                }
            }
        )
        # Mock PIT operations
        mock_client.create_pit = MagicMock(return_value={"pit_id": "test-pit"})
        mock_client.delete_pit = MagicMock()

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Rule"
        mock_rule.severity = "high"
        mock_rule.yaml_content = "title: Test\nlogsource:\n  product: windows\ntags:\n  - attack.execution"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.name = "test-index"
        mock_index_pattern.pattern = "logs-windows-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Patch async functions that require real services
        with patch('app.services.pull_detector.get_app_url', new_callable=AsyncMock) as mock_get_url, \
             patch('app.services.pull_detector.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.pull_detector.should_suppress_alert') as mock_suppress, \
             patch('app.services.pull_detector.publish_alert', new_callable=AsyncMock), \
             patch('app.services.pull_detector.send_alert_notification', new_callable=AsyncMock), \
             patch('app.services.pull_detector.check_correlation', new_callable=AsyncMock) as mock_corr:

            mock_get_url.return_value = "http://localhost:3000"
            mock_enrich.side_effect = lambda db, doc, ip: doc  # Return doc unchanged
            mock_suppress.return_value = False  # Don't suppress any alerts
            mock_corr.return_value = []  # No correlation triggers

            results = await detector.poll_index_pattern(
                index_pattern=mock_index_pattern,
                rules=[mock_rule],
                sigma_service=mock_sigma_service,
                alert_service=mock_alert_service,
                last_poll=datetime.now(UTC) - timedelta(minutes=5),
                db=mock_db,
            )

            assert mock_alert_service.create_alert.call_count == 2
            assert results["matches"] == 2
            assert results["alerts_created"] == 2

    @pytest.mark.asyncio
    async def test_poll_index_pattern_handles_no_matches(
        self, mock_db, mock_sigma_service, mock_alert_service
    ):
        """Should handle case when no documents match."""
        mock_client = MagicMock()
        mock_client.search = MagicMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
        mock_client.create_pit = MagicMock(return_value={"pit_id": "test-pit"})
        mock_client.delete_pit = MagicMock()

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Rule"
        mock_rule.severity = "medium"
        mock_rule.yaml_content = "title: Test\nlogsource:\n  product: test"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.name = "test-index"
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        with patch('app.services.pull_detector.get_app_url', new_callable=AsyncMock) as mock_get_url, \
             patch('app.services.pull_detector.publish_alert', new_callable=AsyncMock), \
             patch('app.services.pull_detector.send_alert_notification', new_callable=AsyncMock):

            mock_get_url.return_value = None

            results = await detector.poll_index_pattern(
                index_pattern=mock_index_pattern,
                rules=[mock_rule],
                sigma_service=mock_sigma_service,
                alert_service=mock_alert_service,
                last_poll=datetime.now(UTC) - timedelta(minutes=5),
                db=mock_db,
            )

            assert results["matches"] == 0
            assert mock_alert_service.create_alert.call_count == 0
