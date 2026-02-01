"""Tests for PullDetector service."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta
from uuid import uuid4

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
        last_poll = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
        now = datetime(2026, 2, 1, 10, 5, 0, tzinfo=timezone.utc)

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
        now = datetime(2026, 2, 1, 10, 5, 0, tzinfo=timezone.utc)

        # When last_poll is None, should default to 1 hour lookback
        result = detector.build_time_filtered_query(base_query, None, now)
        assert "bool" in result


class TestPollIndexPattern:
    @pytest.fixture
    def mock_sigma_service(self):
        service = MagicMock()
        service.translate_rule = MagicMock(
            return_value={"bool": {"must": [{"match": {"event.code": "1"}}]}}
        )
        return service

    @pytest.fixture
    def mock_alert_service(self):
        service = AsyncMock()
        service.create_alert = AsyncMock(return_value={"alert_id": "test-123"})
        return service

    @pytest.mark.asyncio
    async def test_poll_index_pattern_creates_alerts_for_matches(
        self, mock_sigma_service, mock_alert_service
    ):
        """Should create alerts for documents matching deployed rules."""
        mock_client = MagicMock()
        mock_client.search = MagicMock(
            return_value={
                "hits": {
                    "hits": [
                        {"_id": "doc1", "_source": {"message": "suspicious"}},
                        {"_id": "doc2", "_source": {"message": "malware"}},
                    ]
                }
            }
        )

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Rule"
        mock_rule.severity = "high"
        mock_rule.yaml_content = "title: Test\nlogsource:\n  product: windows"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.pattern = "logs-windows-*"

        results = await detector.poll_index_pattern(
            index_pattern=mock_index_pattern,
            rules=[mock_rule],
            sigma_service=mock_sigma_service,
            alert_service=mock_alert_service,
            last_poll=datetime.now(timezone.utc) - timedelta(minutes=5),
        )

        assert mock_alert_service.create_alert.call_count == 2
        assert results["matches"] == 2

    @pytest.mark.asyncio
    async def test_poll_index_pattern_handles_no_matches(
        self, mock_sigma_service, mock_alert_service
    ):
        """Should handle case when no documents match."""
        mock_client = MagicMock()
        mock_client.search = MagicMock(return_value={"hits": {"hits": []}})

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Rule"
        mock_rule.severity = "medium"
        mock_rule.yaml_content = "title: Test"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.pattern = "logs-*"

        results = await detector.poll_index_pattern(
            index_pattern=mock_index_pattern,
            rules=[mock_rule],
            sigma_service=mock_sigma_service,
            alert_service=mock_alert_service,
            last_poll=datetime.now(timezone.utc) - timedelta(minutes=5),
        )

        assert results["matches"] == 0
        assert mock_alert_service.create_alert.call_count == 0
