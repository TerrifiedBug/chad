"""Tests for queue settings service."""

from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.queue import QueueSettings


class TestQueueSettings:
    """Tests for queue settings retrieval."""

    def test_queue_settings_defaults(self):
        """QueueSettings should have sensible defaults."""
        settings = QueueSettings()

        assert settings.max_queue_size == 100000
        assert settings.warning_threshold == 10000
        assert settings.critical_threshold == 50000
        assert settings.backpressure_mode == "drop"
        assert settings.batch_size == 500
        assert settings.batch_timeout_seconds == 5
        assert settings.message_ttl_seconds == 1800  # 30 minutes

    @pytest.mark.asyncio
    async def test_get_queue_settings_from_db(self):
        """Should load settings from database when available."""
        from app.services.queue_settings import get_queue_settings

        mock_db = AsyncMock()

        with patch("app.services.queue_settings.get_setting") as mock_get:
            mock_get.return_value = {
                "max_queue_size": 50000,
                "batch_size": 1000,
            }

            settings = await get_queue_settings(mock_db)

            assert settings.max_queue_size == 50000
            assert settings.batch_size == 1000
            # Defaults for unspecified
            assert settings.warning_threshold == 10000
