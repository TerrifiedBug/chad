"""Tests for LogProcessor service."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.log_processor import LogProcessor


class TestLogProcessorDuplicateAlertPrevention:
    """Tests for duplicate alert prevention in push mode."""

    @pytest.fixture
    def mock_os_client(self):
        """Mock OpenSearch client."""
        return MagicMock()

    @pytest.fixture
    def mock_db_session_factory(self):
        """Mock database session factory."""
        return MagicMock()

    @pytest.fixture
    def mock_db(self):
        """Mock async database session."""
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)
        return db

    @pytest.mark.asyncio
    async def test_sigma_alert_includes_ioc_info_no_duplicate(
        self, mock_os_client, mock_db_session_factory, mock_db
    ):
        """When both Sigma and IOC match, should create 1 Sigma alert with IOC info embedded."""
        processor = LogProcessor(mock_os_client, mock_db_session_factory)

        # Mock the IOC detector to find a match
        mock_ioc_match = MagicMock()
        mock_ioc_match.to_dict.return_value = {
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "misp_event_id": "123",
            "misp_event_info": "Test Event",
            "threat_level": "high",
        }
        processor.ioc_detector.detect_iocs = AsyncMock(return_value=[mock_ioc_match])

        # Mock the alert service
        alert_counter = [0]

        def create_alert_side_effect(**kwargs):
            alert_counter[0] += 1
            return {
                "alert_id": f"test-alert-{alert_counter[0]}",
                "rule_id": kwargs.get("rule_id", "test-rule"),
                "rule_title": kwargs.get("rule_title", "Test Rule"),
                "severity": kwargs.get("severity", "medium"),
                "tags": kwargs.get("tags", []),
                "status": "new",
                "log_document": kwargs.get("log_document", {}),
                "created_at": datetime.now(UTC).isoformat(),
            }

        processor.alert_service.create_alert = MagicMock(side_effect=create_alert_side_effect)

        # Mock index pattern with IOC detection enabled
        mock_index_pattern = MagicMock()
        mock_index_pattern.ioc_detection_enabled = True
        mock_index_pattern.ioc_field_mappings = {"ip": ["src_ip"]}

        logs = [{"message": "test", "src_ip": "1.2.3.4"}]

        with patch.object(processor, '_get_index_pattern', new_callable=AsyncMock) as mock_get_ip, \
             patch('app.services.log_processor.batch_percolate_logs') as mock_percolate, \
             patch('app.services.log_processor.get_app_url', new_callable=AsyncMock) as mock_url, \
             patch('app.services.log_processor.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.log_processor.should_suppress_alert') as mock_suppress, \
             patch('app.services.log_processor.publish_alert', new_callable=AsyncMock), \
             patch('app.services.log_processor.send_alert_notification', new_callable=AsyncMock), \
             patch('app.services.log_processor.check_correlation', new_callable=AsyncMock) as mock_corr:

            mock_get_ip.return_value = mock_index_pattern
            # Simulate log 0 matching a Sigma rule
            mock_percolate.return_value = {
                0: [{"rule_id": str(uuid4()), "rule_title": "Test Sigma Rule", "severity": "high", "tags": [], "enabled": True}]
            }
            mock_url.return_value = None
            mock_enrich.side_effect = lambda db, doc, ip: doc
            mock_suppress.return_value = False
            mock_corr.return_value = []

            result = await processor.process_batch(mock_db, "test-index", logs)

            # Should create exactly 1 alert (the Sigma alert with IOC info embedded)
            assert result["alerts_created"] == 1
            assert processor.alert_service.create_alert.call_count == 1

            # Verify the Sigma alert was created (not an IOC-only alert)
            call_kwargs = processor.alert_service.create_alert.call_args[1]
            assert call_kwargs["rule_title"] == "Test Sigma Rule"
            # IOC info should be in the log_document
            assert "threat_intel" in call_kwargs["log_document"]
            assert call_kwargs["log_document"]["threat_intel"]["has_ioc_match"] is True

    @pytest.mark.asyncio
    async def test_ioc_only_alert_when_no_sigma_match(
        self, mock_os_client, mock_db_session_factory, mock_db
    ):
        """IOC match with no Sigma match should create 1 IOC alert."""
        processor = LogProcessor(mock_os_client, mock_db_session_factory)

        # Mock the IOC detector to find a match
        mock_ioc_match = MagicMock()
        mock_ioc_match.to_dict.return_value = {
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "misp_event_id": "123",
            "misp_event_info": "Test Event",
            "threat_level": "high",
            "tags": ["malware"],
        }
        processor.ioc_detector.detect_iocs = AsyncMock(return_value=[mock_ioc_match])

        alert_counter = [0]

        def create_alert_side_effect(**kwargs):
            alert_counter[0] += 1
            return {
                "alert_id": f"test-alert-{alert_counter[0]}",
                "rule_id": kwargs.get("rule_id", "test-rule"),
                "rule_title": kwargs.get("rule_title", "Test Rule"),
                "severity": kwargs.get("severity", "medium"),
                "tags": kwargs.get("tags", []),
                "status": "new",
                "log_document": kwargs.get("log_document", {}),
                "created_at": datetime.now(UTC).isoformat(),
            }

        processor.alert_service.create_alert = MagicMock(side_effect=create_alert_side_effect)

        mock_index_pattern = MagicMock()
        mock_index_pattern.ioc_detection_enabled = True
        mock_index_pattern.ioc_field_mappings = {"ip": ["src_ip"]}

        logs = [{"message": "test", "src_ip": "1.2.3.4"}]

        with patch.object(processor, '_get_index_pattern', new_callable=AsyncMock) as mock_get_ip, \
             patch('app.services.log_processor.batch_percolate_logs') as mock_percolate, \
             patch('app.services.log_processor.get_app_url', new_callable=AsyncMock) as mock_url, \
             patch('app.services.log_processor.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.log_processor.publish_alert', new_callable=AsyncMock), \
             patch('app.services.log_processor.send_alert_notification', new_callable=AsyncMock):

            mock_get_ip.return_value = mock_index_pattern
            # No Sigma matches
            mock_percolate.return_value = {}
            mock_url.return_value = None
            mock_enrich.side_effect = lambda db, doc, ip: doc

            result = await processor.process_batch(mock_db, "test-index", logs)

            # Should create 1 IOC-only alert
            assert result["alerts_created"] == 1
            assert processor.alert_service.create_alert.call_count == 1

            # Verify it's an IOC alert
            call_kwargs = processor.alert_service.create_alert.call_args[1]
            assert call_kwargs["rule_id"] == "ioc-detection"
            assert "IOC Match" in call_kwargs["rule_title"]

    @pytest.mark.asyncio
    async def test_sigma_suppressed_allows_ioc_alert(
        self, mock_os_client, mock_db_session_factory, mock_db
    ):
        """When Sigma is suppressed by exception, IOC alert should still be created."""
        processor = LogProcessor(mock_os_client, mock_db_session_factory)

        # Mock the IOC detector to find a match
        mock_ioc_match = MagicMock()
        mock_ioc_match.to_dict.return_value = {
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "misp_event_id": "123",
            "misp_event_info": "Test Event",
            "threat_level": "high",
            "tags": [],
        }
        processor.ioc_detector.detect_iocs = AsyncMock(return_value=[mock_ioc_match])

        alert_counter = [0]

        def create_alert_side_effect(**kwargs):
            alert_counter[0] += 1
            return {
                "alert_id": f"test-alert-{alert_counter[0]}",
                "rule_id": kwargs.get("rule_id", "test-rule"),
                "rule_title": kwargs.get("rule_title", "Test Rule"),
                "severity": kwargs.get("severity", "medium"),
                "tags": kwargs.get("tags", []),
                "status": "new",
                "log_document": kwargs.get("log_document", {}),
                "created_at": datetime.now(UTC).isoformat(),
            }

        processor.alert_service.create_alert = MagicMock(side_effect=create_alert_side_effect)

        mock_index_pattern = MagicMock()
        mock_index_pattern.ioc_detection_enabled = True
        mock_index_pattern.ioc_field_mappings = {"ip": ["src_ip"]}

        logs = [{"message": "test", "src_ip": "1.2.3.4"}]

        with patch.object(processor, '_get_index_pattern', new_callable=AsyncMock) as mock_get_ip, \
             patch('app.services.log_processor.batch_percolate_logs') as mock_percolate, \
             patch('app.services.log_processor.get_app_url', new_callable=AsyncMock) as mock_url, \
             patch('app.services.log_processor.enrich_alert', new_callable=AsyncMock) as mock_enrich, \
             patch('app.services.log_processor.should_suppress_alert') as mock_suppress, \
             patch('app.services.log_processor.publish_alert', new_callable=AsyncMock), \
             patch('app.services.log_processor.send_alert_notification', new_callable=AsyncMock):

            mock_get_ip.return_value = mock_index_pattern
            # Sigma rule matches but will be suppressed
            mock_percolate.return_value = {
                0: [{"rule_id": str(uuid4()), "rule_title": "Test Sigma Rule", "severity": "high", "tags": [], "enabled": True}]
            }
            mock_url.return_value = None
            mock_enrich.side_effect = lambda db, doc, ip: doc
            # Suppress the Sigma alert
            mock_suppress.return_value = True

            result = await processor.process_batch(mock_db, "test-index", logs)

            # Should create 1 IOC alert (Sigma was suppressed)
            assert result["alerts_created"] == 1
            assert result["suppressed"] == 1
            assert processor.alert_service.create_alert.call_count == 1

            # Verify it's an IOC alert, not Sigma
            call_kwargs = processor.alert_service.create_alert.call_args[1]
            assert call_kwargs["rule_id"] == "ioc-detection"
