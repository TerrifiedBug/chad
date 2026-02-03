"""Tests for IOC detection in log processing."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.api.deps import get_opensearch_client_optional
from app.main import app


@pytest.fixture
def sample_logs():
    """Sample log batch with IOC."""
    return [
        {
            "@timestamp": "2026-02-03T20:00:00Z",
            "destination.ip": "192.168.1.100",
            "message": "Outbound connection",
        }
    ]


@pytest.fixture
def mock_opensearch():
    """Mock OpenSearch client."""
    mock_os = MagicMock()
    mock_os.indices.exists.return_value = True
    return mock_os


@pytest.mark.asyncio
async def test_logs_with_ioc_detection_enabled(
    client: AsyncClient,
    sample_logs: list,
    mock_opensearch,
):
    """Test log processing with IOC detection enabled."""
    # Mock index pattern with IOC detection enabled
    mock_pattern = MagicMock()
    mock_pattern.id = "test-pattern-id"
    mock_pattern.name = "test-pattern"
    mock_pattern.mode = "push"
    mock_pattern.ioc_detection_enabled = True
    mock_pattern.ioc_field_mappings = {
        "ip-dst": ["destination.ip"],
    }
    mock_pattern.percolator_index = "chad-percolator-test"
    mock_pattern.auth_token = "test-token"
    mock_pattern.allowed_ips = None
    mock_pattern.rate_limit_enabled = False

    # Mock IOC match
    mock_match = MagicMock()
    mock_match.ioc_type.value = "ip-dst"
    mock_match.value = "192.168.1.100"
    mock_match.misp_event_id = "4521"
    mock_match.threat_level = "high"
    mock_match.tags = ["apt29"]
    mock_match.to_dict.return_value = {
        "ioc_type": "ip-dst",
        "value": "192.168.1.100",
        "misp_event_id": "4521",
        "threat_level": "high",
    }

    # Override OpenSearch dependency
    app.dependency_overrides[get_opensearch_client_optional] = lambda: mock_opensearch

    try:
        with patch(
            "app.api.logs.validate_log_shipping_token", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = mock_pattern

            with patch(
                "app.api.logs.IOCDetector"
            ) as MockDetector:
                mock_detector = AsyncMock()
                mock_detector.detect_iocs.return_value = [mock_match]
                MockDetector.return_value = mock_detector

                with patch(
                    "app.api.logs.AlertService"
                ) as MockAlertService:
                    mock_alert_service = MagicMock()
                    mock_alert_service.match_log.return_value = []  # No behavioral matches
                    mock_alert_service.create_alert.return_value = {
                        "alert_id": "test-alert-id",
                        "rule_title": "IOC Match: ip-dst",
                        "severity": "high",
                        "created_at": "2026-02-03T20:00:00Z",
                    }
                    MockAlertService.return_value = mock_alert_service

                    response = await client.post(
                        "/api/logs/test",
                        json=sample_logs,
                        headers={"Authorization": "Bearer test-token"},
                    )

                    assert response.status_code == 200
                    # IOC detection should have been called
                    mock_detector.detect_iocs.assert_called_once()
    finally:
        # Clean up dependency override
        app.dependency_overrides.pop(get_opensearch_client_optional, None)


@pytest.mark.asyncio
async def test_logs_ioc_detection_disabled(
    client: AsyncClient,
    sample_logs: list,
    mock_opensearch,
):
    """Test log processing with IOC detection disabled."""
    mock_pattern = MagicMock()
    mock_pattern.id = "test-pattern-id"
    mock_pattern.name = "test-pattern"
    mock_pattern.mode = "push"
    mock_pattern.ioc_detection_enabled = False
    mock_pattern.ioc_field_mappings = None
    mock_pattern.percolator_index = "chad-percolator-test"
    mock_pattern.auth_token = "test-token"
    mock_pattern.allowed_ips = None
    mock_pattern.rate_limit_enabled = False

    # Override OpenSearch dependency
    app.dependency_overrides[get_opensearch_client_optional] = lambda: mock_opensearch

    try:
        with patch(
            "app.api.logs.validate_log_shipping_token", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = mock_pattern

            with patch(
                "app.api.logs.IOCDetector"
            ) as MockDetector:
                mock_detector = AsyncMock()
                MockDetector.return_value = mock_detector

                with patch(
                    "app.api.logs.AlertService"
                ) as MockAlertService:
                    mock_alert_service = MagicMock()
                    mock_alert_service.match_log.return_value = []
                    MockAlertService.return_value = mock_alert_service

                    response = await client.post(
                        "/api/logs/test",
                        json=sample_logs,
                        headers={"Authorization": "Bearer test-token"},
                    )

                    assert response.status_code == 200
                    # IOC detection should NOT have been called
                    mock_detector.detect_iocs.assert_not_called()
    finally:
        # Clean up dependency override
        app.dependency_overrides.pop(get_opensearch_client_optional, None)
