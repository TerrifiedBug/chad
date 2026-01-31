"""Tests for worker process."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestWorker:
    """Tests for Worker class."""

    def test_worker_initializes_with_running_true(self):
        """Worker should initialize with running=True."""
        from app.worker import Worker

        worker = Worker()

        assert worker.running is True
        assert worker.processing is False

    def test_shutdown_sets_running_false(self):
        """shutdown() should set running to False."""
        from app.worker import Worker

        worker = Worker()
        worker.running = True

        worker.shutdown()

        assert worker.running is False

    @pytest.mark.asyncio
    async def test_worker_has_process_batch_method(self):
        """Worker should have process_batch method."""
        from app.worker import Worker

        worker = Worker()

        assert hasattr(worker, "process_batch")
        assert callable(worker.process_batch)

    @pytest.mark.asyncio
    async def test_worker_has_run_method(self):
        """Worker should have run method."""
        from app.worker import Worker

        worker = Worker()

        assert hasattr(worker, "run")
        assert callable(worker.run)


class TestLogProcessor:
    """Tests for LogProcessor class."""

    @pytest.mark.asyncio
    async def test_log_processor_initializes(self):
        """LogProcessor should initialize with client and session factory."""
        from app.services.log_processor import LogProcessor

        mock_client = MagicMock()
        mock_session_factory = MagicMock()

        processor = LogProcessor(mock_client, mock_session_factory)

        assert processor.os_client == mock_client
        assert processor.db_session_factory == mock_session_factory

    @pytest.mark.asyncio
    async def test_process_batch_returns_stats(self):
        """process_batch should return processing stats."""
        from app.services.log_processor import LogProcessor

        mock_client = MagicMock()
        mock_session_factory = MagicMock()
        mock_db_session = AsyncMock()

        # Mock batch_percolate_logs to return no matches
        # Mock settings.get_app_url to return None
        with patch("app.services.log_processor.batch_percolate_logs", return_value={}), \
             patch("app.services.log_processor.get_app_url", new_callable=AsyncMock, return_value=None):
            # Mock the index pattern lookup to return None
            mock_db_session.execute = AsyncMock()
            mock_db_session.execute.return_value.scalar_one_or_none.return_value = None

            processor = LogProcessor(mock_client, mock_session_factory)
            result = await processor.process_batch(mock_db_session, "test", [{"message": "test"}])

        assert "logs_processed" in result
        assert "matches" in result
        assert "alerts_created" in result
        assert result["logs_processed"] == 1
        assert result["matches"] == 0
        assert result["alerts_created"] == 0
