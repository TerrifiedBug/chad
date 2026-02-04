"""Tests for MISP sync scheduler integration."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scheduler import SchedulerService


@pytest.fixture
def scheduler_service():
    """Create scheduler service for testing."""
    return SchedulerService()


@pytest.mark.asyncio
async def test_run_misp_sync_job(scheduler_service):
    """Test MISP sync job executes successfully."""
    mock_sync_result = MagicMock()
    mock_sync_result.success = True
    mock_sync_result.iocs_fetched = 100
    mock_sync_result.iocs_cached = 100
    mock_sync_result.iocs_indexed = 100
    mock_sync_result.duration_ms = 5000

    with patch.object(
        scheduler_service, "_create_misp_sync_service", new_callable=AsyncMock
    ) as mock_create:
        mock_service = AsyncMock()
        mock_service.sync_iocs.return_value = mock_sync_result
        mock_create.return_value = mock_service

        # Mock settings to enable MISP sync
        with patch.object(
            scheduler_service, "_get_misp_sync_settings", new_callable=AsyncMock
        ) as mock_settings:
            mock_settings.return_value = {
                "enabled": True,
                "interval_minutes": 10,
                "threat_levels": ["high", "medium"],
                "max_age_days": 30,
            }

            with patch("app.services.scheduler.logger"):
                await scheduler_service._run_misp_sync_job()

            mock_service.sync_iocs.assert_called_once()


@pytest.mark.asyncio
async def test_run_misp_sync_job_disabled(scheduler_service):
    """Test MISP sync job skipped when disabled."""
    with patch.object(
        scheduler_service, "_get_misp_sync_settings", new_callable=AsyncMock
    ) as mock_settings:
        mock_settings.return_value = {"enabled": False}

        with patch.object(
            scheduler_service, "_create_misp_sync_service", new_callable=AsyncMock
        ) as mock_create:
            await scheduler_service._run_misp_sync_job()

            # Should not create service when disabled
            mock_create.assert_not_called()


@pytest.mark.asyncio
async def test_run_misp_sync_job_logs_errors(scheduler_service):
    """Test MISP sync job logs errors on failure."""
    mock_sync_result = MagicMock()
    mock_sync_result.success = False
    mock_sync_result.error = "MISP connection timeout"

    with patch.object(
        scheduler_service, "_create_misp_sync_service", new_callable=AsyncMock
    ) as mock_create:
        mock_service = AsyncMock()
        mock_service.sync_iocs.return_value = mock_sync_result
        mock_create.return_value = mock_service

        with patch.object(
            scheduler_service, "_get_misp_sync_settings", new_callable=AsyncMock
        ) as mock_settings:
            mock_settings.return_value = {"enabled": True}

            with patch("app.services.scheduler.logger") as mock_logger:
                with patch("app.services.scheduler.system_log_service") as mock_sys_log:
                    mock_sys_log.log_error = AsyncMock()
                    await scheduler_service._run_misp_sync_job()

                    # Should log the error
                    mock_logger.error.assert_called()
                    mock_sys_log.log_error.assert_called_once()
