"""Tests for queue management API."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestQueueSettingsAPI:
    """Tests for queue settings endpoints."""

    @pytest.mark.asyncio
    async def test_get_settings_returns_defaults(self):
        """GET /queue/settings should return queue settings."""
        from app.schemas.queue import QueueSettings

        # Test that schema has expected defaults
        settings = QueueSettings()
        assert settings.max_queue_size == 100000
        assert settings.batch_size == 500

    @pytest.mark.asyncio
    async def test_queue_settings_update_schema(self):
        """QueueSettingsUpdate should allow partial updates."""
        from app.schemas.queue import QueueSettingsUpdate

        update = QueueSettingsUpdate(batch_size=1000)
        assert update.batch_size == 1000
        assert update.max_queue_size is None


class TestQueueStatsAPI:
    """Tests for queue stats endpoint."""

    @pytest.mark.asyncio
    async def test_queue_stats_response_model(self):
        """QueueStatsResponse should have expected fields."""
        from app.api.queue import QueueStatsResponse

        stats = QueueStatsResponse(
            total_depth=100,
            queues={"test": 50, "prod": 50},
            dead_letter_count=5,
        )
        assert stats.total_depth == 100
        assert stats.dead_letter_count == 5


class TestDeadLetterAPI:
    """Tests for dead letter queue endpoints."""

    @pytest.mark.asyncio
    async def test_dead_letter_message_model(self):
        """DeadLetterMessage should have expected fields."""
        from app.api.queue import DeadLetterMessage

        msg = DeadLetterMessage(
            id="1234-0",
            original_stream="chad:logs:test",
            original_id="5678-0",
            data={"message": "test"},
            reason="TTL exceeded",
        )
        assert msg.id == "1234-0"
        assert msg.reason == "TTL exceeded"

    @pytest.mark.asyncio
    async def test_dead_letter_response_model(self):
        """DeadLetterResponse should contain count and messages."""
        from app.api.queue import DeadLetterResponse, DeadLetterMessage

        msg = DeadLetterMessage(
            id="1234-0",
            original_stream="test",
            original_id="5678-0",
            data={},
            reason="TTL",
        )
        response = DeadLetterResponse(count=1, messages=[msg])
        assert response.count == 1
        assert len(response.messages) == 1
