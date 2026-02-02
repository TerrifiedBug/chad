"""Tests for Prometheus metrics endpoint."""

from unittest.mock import AsyncMock, patch

import pytest


class TestMetricsEndpoint:
    """Tests for /metrics endpoint."""

    @pytest.mark.asyncio
    async def test_metrics_returns_prometheus_format(self):
        """Metrics endpoint should return Prometheus format."""
        from app.api.metrics import metrics

        # Mock Redis to return empty queues
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        mock_redis.scan = AsyncMock(return_value=(0, []))
        mock_redis.xlen = AsyncMock(return_value=0)

        with patch("app.api.metrics.get_redis", return_value=mock_redis):
            result = await metrics()

        assert "chad_queue_depth_total" in result
        assert "chad_dead_letter_count" in result
        assert "chad_redis_connected 1" in result

    @pytest.mark.asyncio
    async def test_metrics_handles_redis_unavailable(self):
        """Metrics should return zeros when Redis unavailable."""
        from app.api.metrics import metrics

        with patch("app.api.metrics.get_redis", side_effect=Exception("Connection failed")):
            result = await metrics()

        assert "chad_redis_connected 0" in result
        assert "chad_queue_depth_total 0" in result

    @pytest.mark.asyncio
    async def test_metrics_includes_queue_depths(self):
        """Metrics should include per-index queue depths."""
        from app.api.metrics import metrics

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        mock_redis.scan = AsyncMock(side_effect=[
            (0, ["chad:logs:windows", "chad:logs:linux"]),
        ])
        mock_redis.xlen = AsyncMock(side_effect=[100, 50, 5])  # windows, linux, dead-letter

        with patch("app.api.metrics.get_redis", return_value=mock_redis):
            result = await metrics()

        assert 'chad_queue_depth{index="windows"} 100' in result
        assert 'chad_queue_depth{index="linux"} 50' in result
        assert "chad_queue_depth_total 150" in result
