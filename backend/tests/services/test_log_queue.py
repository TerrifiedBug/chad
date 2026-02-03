"""Tests for log queue service."""

from unittest.mock import AsyncMock

import pytest


class TestLogQueueService:
    """Tests for LogQueueService."""

    @pytest.mark.asyncio
    async def test_enqueue_logs_adds_to_stream(self):
        """enqueue_logs should add logs to Redis stream."""
        from app.services.log_queue import LogQueueService

        mock_redis = AsyncMock()
        mock_redis.xlen.return_value = 5

        service = LogQueueService(mock_redis)

        logs = [{"message": "test1"}, {"message": "test2"}]
        result = await service.enqueue_logs("windows", logs)

        assert result["queued"] == 2
        assert result["queue_depth"] == 5
        assert mock_redis.xadd.call_count == 2

    @pytest.mark.asyncio
    async def test_enqueue_logs_respects_maxlen(self):
        """enqueue_logs should use maxlen to limit stream size."""
        from app.services.log_queue import LogQueueService

        mock_redis = AsyncMock()
        mock_redis.xlen.return_value = 10

        service = LogQueueService(mock_redis, max_queue_size=50000)

        await service.enqueue_logs("test", [{"msg": "test"}])

        # Verify maxlen was passed
        call_args = mock_redis.xadd.call_args
        assert call_args.kwargs.get("maxlen") == 50000

    @pytest.mark.asyncio
    async def test_get_queue_depth(self):
        """get_queue_depth should return stream length."""
        from app.services.log_queue import LogQueueService

        mock_redis = AsyncMock()
        mock_redis.xlen.return_value = 1234

        service = LogQueueService(mock_redis)

        depth = await service.get_queue_depth("windows")

        assert depth == 1234
        mock_redis.xlen.assert_called_with("chad:logs:windows")
