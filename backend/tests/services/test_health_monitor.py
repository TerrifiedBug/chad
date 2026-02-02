"""Tests for health monitor service functions."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.health_monitor import check_index_data_freshness


class TestCheckIndexDataFreshness:
    """Tests for check_index_data_freshness function."""

    @pytest.mark.asyncio
    async def test_fresh_data_returns_true(self):
        """Data from 5 minutes ago should be considered fresh (within 15 min default)."""
        # Arrange
        mock_client = AsyncMock()
        five_minutes_ago = datetime.now(UTC) - timedelta(minutes=5)
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "@timestamp": five_minutes_ago.isoformat()
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is True
        assert details["status"] == "fresh"
        assert "last_event_at" in details
        assert "age_minutes" in details
        assert details["age_minutes"] <= 6  # Allow some tolerance for test execution time
        assert details["threshold_minutes"] == 15
        assert details["index"] == "logs-*"

    @pytest.mark.asyncio
    async def test_stale_data_returns_false(self):
        """Data from 30 minutes ago should be considered stale (beyond 15 min default)."""
        # Arrange
        mock_client = AsyncMock()
        thirty_minutes_ago = datetime.now(UTC) - timedelta(minutes=30)
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "@timestamp": thirty_minutes_ago.isoformat()
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "stale"
        assert "last_event_at" in details
        assert details["age_minutes"] >= 29  # Allow some tolerance
        assert details["threshold_minutes"] == 15
        assert details["index"] == "logs-*"

    @pytest.mark.asyncio
    async def test_no_data_returns_false(self):
        """Empty index (no hits) should return no_data status."""
        # Arrange
        mock_client = AsyncMock()
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 0},
                "hits": []
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "empty-index-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "no_data"
        assert details["message"] == "No events found in index"
        assert details["index"] == "empty-index-*"

    @pytest.mark.asyncio
    async def test_missing_timestamp_field_returns_false(self):
        """Document without timestamp field should return no_timestamp status."""
        # Arrange
        mock_client = AsyncMock()
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "message": "some log without timestamp"
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "no_timestamp"
        assert "@timestamp" in details["message"]
        assert details["index"] == "logs-*"

    @pytest.mark.asyncio
    async def test_opensearch_error_returns_false(self):
        """OpenSearch exception should return error status."""
        # Arrange
        mock_client = AsyncMock()
        mock_client.search = AsyncMock(side_effect=Exception("Connection refused"))

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "error"
        assert "Connection refused" in details["message"]
        assert details["index"] == "logs-*"

    @pytest.mark.asyncio
    async def test_uses_custom_timestamp_field(self):
        """Should use the custom timestamp field from index_pattern."""
        # Arrange
        mock_client = AsyncMock()
        five_minutes_ago = datetime.now(UTC) - timedelta(minutes=5)
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "event": {
                                "created": five_minutes_ago.isoformat()
                            }
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "event.created"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is True
        assert details["status"] == "fresh"

        # Verify the search was called with correct sort field
        mock_client.search.assert_called_once()
        call_kwargs = mock_client.search.call_args[1]
        assert "sort" in call_kwargs["body"]
        sort_field = list(call_kwargs["body"]["sort"][0].keys())[0]
        assert sort_field == "event.created"

    @pytest.mark.asyncio
    async def test_nested_timestamp_field_missing(self):
        """Should handle missing nested timestamp field gracefully."""
        # Arrange
        mock_client = AsyncMock()
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "event": {
                                "other_field": "value"
                            }
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        mock_index_pattern.timestamp_field = "event.created"

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "no_timestamp"
        assert "event.created" in details["message"]

    @pytest.mark.asyncio
    async def test_default_timestamp_field_when_not_set(self):
        """Should use @timestamp as default when timestamp_field is not set."""
        # Arrange
        mock_client = AsyncMock()
        five_minutes_ago = datetime.now(UTC) - timedelta(minutes=5)
        mock_client.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_source": {
                            "@timestamp": five_minutes_ago.isoformat()
                        }
                    }
                ]
            }
        })

        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-*"
        # Simulate timestamp_field not being set (returns None or default)
        mock_index_pattern.timestamp_field = None

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is True
        assert details["status"] == "fresh"

        # Verify @timestamp was used
        call_kwargs = mock_client.search.call_args[1]
        sort_field = list(call_kwargs["body"]["sort"][0].keys())[0]
        assert sort_field == "@timestamp"

    @pytest.mark.asyncio
    async def test_epoch_milliseconds_timestamp(self):
        """Should correctly parse Unix epoch milliseconds."""
        # Arrange
        mock_client = AsyncMock()
        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-test-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # 5 minutes ago in epoch milliseconds
        fresh_epoch_ms = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp() * 1000)
        mock_client.search.return_value = {
            "hits": {
                "hits": [{"_source": {"@timestamp": fresh_epoch_ms}}]
            }
        }

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is True
        assert details["status"] == "fresh"
        assert details["age_minutes"] <= 6  # Allow some slack

    @pytest.mark.asyncio
    async def test_epoch_seconds_timestamp(self):
        """Should correctly parse Unix epoch seconds."""
        # Arrange
        mock_client = AsyncMock()
        mock_index_pattern = MagicMock()
        mock_index_pattern.pattern = "logs-test-*"
        mock_index_pattern.timestamp_field = "@timestamp"

        # 30 minutes ago in epoch seconds
        stale_epoch_sec = int((datetime.now(UTC) - timedelta(minutes=30)).timestamp())
        mock_client.search.return_value = {
            "hits": {
                "hits": [{"_source": {"@timestamp": stale_epoch_sec}}]
            }
        }

        # Act
        is_fresh, details = await check_index_data_freshness(
            mock_client, mock_index_pattern, threshold_minutes=15
        )

        # Assert
        assert is_fresh is False
        assert details["status"] == "stale"
        assert details["age_minutes"] >= 15
