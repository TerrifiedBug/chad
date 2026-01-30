# backend/tests/services/test_scheduler_locking.py
"""Tests for scheduler distributed locking."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestSchedulerLocking:
    """Tests for distributed lock acquisition in scheduled jobs."""

    @pytest.mark.asyncio
    async def test_job_skipped_when_lock_not_acquired(self):
        """Job should skip execution when lock is held by another worker."""
        from app.services.scheduler import SchedulerService

        service = SchedulerService()

        # Mock Redis client where lock acquisition fails
        mock_redis = MagicMock()
        mock_lock = AsyncMock()
        mock_lock.acquire.return_value = False  # Lock not acquired
        mock_redis.lock.return_value = mock_lock

        # get_redis is async, so we need an async mock
        async def mock_get_redis():
            return mock_redis

        with patch("app.services.scheduler.get_redis", mock_get_redis):
            # Mock the actual health check to track if it's called
            with patch.object(service, "_execute_health_check", new_callable=AsyncMock) as mock_execute:
                await service._run_health_check_with_lock()

                # Health check should NOT be executed
                mock_execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_job_executes_when_lock_acquired(self):
        """Job should execute when lock is successfully acquired."""
        from app.services.scheduler import SchedulerService

        service = SchedulerService()

        # Mock Redis client where lock acquisition succeeds
        mock_redis = MagicMock()
        mock_lock = AsyncMock()
        mock_lock.acquire.return_value = True  # Lock acquired
        mock_redis.lock.return_value = mock_lock

        async def mock_get_redis():
            return mock_redis

        with patch("app.services.scheduler.get_redis", mock_get_redis):
            with patch.object(service, "_execute_health_check", new_callable=AsyncMock) as mock_execute:
                await service._run_health_check_with_lock()

                # Health check SHOULD be executed
                mock_execute.assert_called_once()

                # Lock should be released
                mock_lock.release.assert_called_once()

    @pytest.mark.asyncio
    async def test_lock_released_even_on_exception(self):
        """Lock should be released even if job raises exception."""
        from app.services.scheduler import SchedulerService

        service = SchedulerService()

        mock_redis = MagicMock()
        mock_lock = AsyncMock()
        mock_lock.acquire.return_value = True
        mock_redis.lock.return_value = mock_lock

        async def mock_get_redis():
            return mock_redis

        async def raise_error():
            raise Exception("Test error")

        with patch("app.services.scheduler.get_redis", mock_get_redis):
            with patch.object(service, "_execute_health_check", raise_error):
                # Should not raise
                await service._run_health_check_with_lock()

                # Lock should still be released
                mock_lock.release.assert_called_once()

    @pytest.mark.asyncio
    async def test_job_runs_without_lock_when_redis_unavailable(self):
        """Job should run without lock when Redis is unavailable (graceful degradation)."""
        from app.services.scheduler import SchedulerService

        service = SchedulerService()

        async def mock_get_redis():
            raise Exception("Redis connection failed")

        with patch("app.services.scheduler.get_redis", mock_get_redis):
            with patch.object(service, "_execute_health_check", new_callable=AsyncMock) as mock_execute:
                await service._run_health_check_with_lock()

                # Health check SHOULD still be executed (fallback to no-lock)
                mock_execute.assert_called_once()


class TestRunWithLock:
    """Tests for the _run_with_lock utility method."""

    @pytest.mark.asyncio
    async def test_run_with_lock_uses_correct_timeout(self):
        """Lock should be created with the specified timeout."""
        from app.services.scheduler import SchedulerService

        service = SchedulerService()

        mock_redis = MagicMock()
        mock_lock = AsyncMock()
        mock_lock.acquire.return_value = True
        mock_redis.lock.return_value = mock_lock

        async def mock_get_redis():
            return mock_redis

        with patch("app.services.scheduler.get_redis", mock_get_redis):
            job_func = AsyncMock()
            await service._run_with_lock("test:lock", timeout=120, job_func=job_func)

            # Verify lock was created with correct parameters
            mock_redis.lock.assert_called_once_with("test:lock", timeout=120, blocking=False)
