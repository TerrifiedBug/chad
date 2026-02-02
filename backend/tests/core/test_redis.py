# backend/tests/core/test_redis.py
"""Tests for Redis client module."""

from unittest.mock import AsyncMock, patch

import pytest


class TestGetRedis:
    """Tests for get_redis function."""

    @pytest.mark.asyncio
    async def test_get_redis_creates_client_on_first_call(self):
        """First call should create a new Redis client."""
        from app.core import redis as redis_module

        # Reset global state
        redis_module.redis_client = None

        with patch.object(redis_module.redis, 'from_url') as mock_from_url:
            mock_client = AsyncMock()
            mock_from_url.return_value = mock_client

            result = await redis_module.get_redis()

            mock_from_url.assert_called_once()
            assert result == mock_client

    @pytest.mark.asyncio
    async def test_get_redis_reuses_existing_client(self):
        """Subsequent calls should reuse existing client."""
        from app.core import redis as redis_module

        mock_client = AsyncMock()
        redis_module.redis_client = mock_client

        with patch.object(redis_module.redis, 'from_url') as mock_from_url:
            result = await redis_module.get_redis()

            mock_from_url.assert_not_called()
            assert result == mock_client

        # Cleanup
        redis_module.redis_client = None


class TestCloseRedis:
    """Tests for close_redis function."""

    @pytest.mark.asyncio
    async def test_close_redis_closes_and_clears_client(self):
        """close_redis should close client and set to None."""
        from app.core import redis as redis_module

        mock_client = AsyncMock()
        redis_module.redis_client = mock_client

        await redis_module.close_redis()

        mock_client.close.assert_called_once()
        assert redis_module.redis_client is None

    @pytest.mark.asyncio
    async def test_close_redis_handles_no_client(self):
        """close_redis should handle case when no client exists."""
        from app.core import redis as redis_module

        redis_module.redis_client = None

        # Should not raise
        await redis_module.close_redis()

        assert redis_module.redis_client is None
