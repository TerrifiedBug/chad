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


class TestDuplicateAlertPrevention:
    """Tests for duplicate alert prevention when both Sigma and IOC match."""

    @pytest.fixture
    def mock_db(self):
        """Mock async database session."""
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=mock_result)
        return db

    @pytest.fixture
    def mock_sigma_service(self):
        """Mock SigmaService with successful translation."""
        service = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.query = {"query": {"query_string": {"query": "event.code:1"}}}
        mock_result.fields = set()
        mock_result.errors = None
        service.translate_and_validate = MagicMock(return_value=mock_result)
        return service

    @pytest.fixture
    def mock_alert_service(self):
        """Mock AlertService."""
        service = MagicMock()
        alert_counter = [0]

        def create_alert_side_effect(**kwargs):
            alert_counter[0] += 1
            return {
                "alert_id": f"test-alert-{alert_counter[0]}",
                "rule_id": kwargs.get("rule_id", "test-rule"),
                "rule_title": kwargs.get("rule_title", "Test Rule"),
                "severity": kwargs.get("severity", "high"),
                "tags": kwargs.get("tags", []),
                "status": "new",
                "log_document": kwargs.get("log_document", {}),
                "created_at": datetime.now(UTC).isoformat(),
            }

        service.create_alert = MagicMock(side_effect=create_alert_side_effect)
        return service

    @pytest.mark.asyncio
    async def test_sigma_match_only_creates_one_alert(
        self, mock_db, mock_sigma_service, mock_alert_service
    ):
        """Sigma match with no IOC should create 1 Sigma alert."""
        mock_client = MagicMock()
        mock_client.search = MagicMock(
            return_value={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [
                        {"_id": "doc1", "_source": {"message": "suspicious"}, "sort": [1, "doc1"]},
                    ]
                }
            }
        )
        mock_client.create_pit = MagicMock(return_value={"pit_id": "test-pit"})
        mock_client.delete_pit = MagicMock()
        mock_client.indices = MagicMock()
        mock_client.indices.exists = MagicMock(return_value=False)  # No IOC index

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Sigma Rule"
        mock_rule.severity = "high"
        mock_rule.yaml_content = "title: Test\nlogsource:\n  product: windows"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.name = "test-index"
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"
        mock_index_pattern.poll_interval_minutes = 5
        mock_index_pattern.ioc_detection_enabled = False

        with patch('app.services.pull_detector.get_app_url', new_callable=AsyncMock) as mock_get_url, \
             patch('app.services.pull_detector.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.pull_detector.should_suppress_alert') as mock_suppress, \
             patch('app.services.pull_detector.publish_alert', new_callable=AsyncMock), \
             patch('app.services.pull_detector.send_alert_notification', new_callable=AsyncMock), \
             patch('app.services.pull_detector.check_correlation', new_callable=AsyncMock) as mock_corr:

            mock_get_url.return_value = None
            mock_enrich.side_effect = lambda db, doc, ip: doc
            mock_suppress.return_value = False
            mock_corr.return_value = []

            results = await detector.poll_index_pattern(
                index_pattern=mock_index_pattern,
                rules=[mock_rule],
                sigma_service=mock_sigma_service,
                alert_service=mock_alert_service,
                last_poll=datetime.now(UTC) - timedelta(minutes=5),
                db=mock_db,
            )

            # Should create exactly 1 Sigma alert
            assert results["matches"] == 1
            assert results["alerts_created"] == 1
            assert mock_alert_service.create_alert.call_count == 1
            # Verify it's the Sigma rule alert
            call_kwargs = mock_alert_service.create_alert.call_args[1]
            assert call_kwargs["rule_title"] == "Test Sigma Rule"

    @pytest.mark.asyncio
    async def test_both_sigma_and_ioc_match_creates_one_alert(
        self, mock_db, mock_sigma_service, mock_alert_service
    ):
        """Same doc matching both Sigma and IOC should create only 1 Sigma alert."""
        mock_client = MagicMock()

        # Sigma search returns doc1
        sigma_response = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {"_id": "doc1", "_source": {"message": "suspicious", "src_ip": "1.2.3.4"}, "sort": [1, "doc1"]},
                ]
            }
        }
        # IOC search also returns doc1 (same document)
        ioc_response = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {"_id": "doc1", "_source": {"message": "suspicious", "src_ip": "1.2.3.4"}, "sort": [1, "doc1"]},
                ]
            }
        }

        call_count = [0]

        def search_side_effect(*args, **kwargs):
            call_count[0] += 1
            # First calls are for Sigma rules, later for IOC
            if call_count[0] <= 1:
                return sigma_response
            return ioc_response

        mock_client.search = MagicMock(side_effect=search_side_effect)
        mock_client.create_pit = MagicMock(return_value={"pit_id": "test-pit"})
        mock_client.delete_pit = MagicMock()
        mock_client.indices = MagicMock()
        mock_client.indices.exists = MagicMock(return_value=True)  # IOC index exists

        detector = PullDetector(client=mock_client)

        mock_rule = MagicMock()
        mock_rule.id = uuid4()
        mock_rule.title = "Test Sigma Rule"
        mock_rule.severity = "high"
        mock_rule.yaml_content = "title: Test\nlogsource:\n  product: windows"

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.name = "test-index"
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"
        mock_index_pattern.poll_interval_minutes = 5
        mock_index_pattern.ioc_detection_enabled = True
        mock_index_pattern.ioc_field_mappings = {"ip": ["src_ip"]}

        with patch('app.services.pull_detector.get_app_url', new_callable=AsyncMock) as mock_get_url, \
             patch('app.services.pull_detector.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.pull_detector.should_suppress_alert') as mock_suppress, \
             patch('app.services.pull_detector.publish_alert', new_callable=AsyncMock), \
             patch('app.services.pull_detector.send_alert_notification', new_callable=AsyncMock), \
             patch('app.services.pull_detector.check_correlation', new_callable=AsyncMock) as mock_corr:

            mock_get_url.return_value = None
            mock_enrich.side_effect = lambda db, doc, ip: doc
            mock_suppress.return_value = False
            mock_corr.return_value = []

            results = await detector.poll_index_pattern(
                index_pattern=mock_index_pattern,
                rules=[mock_rule],
                sigma_service=mock_sigma_service,
                alert_service=mock_alert_service,
                last_poll=datetime.now(UTC) - timedelta(minutes=5),
                db=mock_db,
            )

            # Should create exactly 1 alert (Sigma), not 2
            # The IOC match should be skipped because doc1 already has a Sigma alert
            assert results["matches"] == 1
            # IOC alerts should be 0 because doc1 was excluded
            assert results["ioc_alerts"] == 0

    @pytest.mark.asyncio
    async def test_run_ioc_detection_excludes_specified_doc_ids(
        self, mock_db, mock_sigma_service, mock_alert_service
    ):
        """_run_ioc_detection should skip documents in exclude_doc_ids set."""
        mock_client = MagicMock()

        # IOC search returns doc1 and doc3
        ioc_response = {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {"_id": "doc1", "_source": {"message": "suspicious", "src_ip": "1.2.3.4"}, "sort": [1, "doc1"]},
                    {"_id": "doc3", "_source": {"message": "ioc-only", "src_ip": "9.10.11.12"}, "sort": [3, "doc3"]},
                ]
            }
        }

        mock_client.search = MagicMock(return_value=ioc_response)
        mock_client.indices = MagicMock()
        mock_client.indices.exists = MagicMock(return_value=True)

        detector = PullDetector(client=mock_client)

        mock_index_pattern = MagicMock()
        mock_index_pattern.id = uuid4()
        mock_index_pattern.name = "test-index"
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"
        mock_index_pattern.poll_interval_minutes = 5
        mock_index_pattern.ioc_detection_enabled = True
        mock_index_pattern.ioc_field_mappings = {"ip": ["src_ip"]}

        # Mock _identify_matched_ioc to return IOC info for doc3 only
        async def mock_identify_ioc(log_doc, field_mappings):
            if log_doc.get("src_ip") == "9.10.11.12":
                return {
                    "ioc_type": "ip",
                    "value": "9.10.11.12",
                    "misp_event_id": "123",
                    "misp_event_info": "Test MISP Event",
                    "threat_level": "high",
                    "tags": ["malware"],
                }
            return None

        with patch.object(detector, '_identify_matched_ioc', side_effect=mock_identify_ioc), \
             patch('app.services.pull_detector.enrich_alert', new_callable=AsyncMock) as mock_enrich:
            mock_enrich.side_effect = lambda db, doc, ip: doc

            # Run IOC detection with doc1 excluded (simulating it already has a Sigma alert)
            result = await detector._run_ioc_detection(
                index_pattern=mock_index_pattern,
                alert_service=mock_alert_service,
                alerts_index="chad-alerts-test",
                timestamp_field="@timestamp",
                lookback_minutes=5,
                db=mock_db,
                exclude_doc_ids={"doc1"},  # doc1 should be excluded
            )

            # doc1 should be skipped due to exclude_doc_ids, doc3 should be processed
            # The total matches from OpenSearch is 2
            assert result["ioc_matches"] == 2  # Raw count from OpenSearch
            # Only 1 alert should be created (doc3), doc1 was excluded
            assert result["ioc_alerts"] == 1
