"""Tests for health monitor service functions."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.health_monitor import check_index_data_freshness, check_index_health


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


class TestCheckIndexHealthDataFreshnessIntegration:
    """Tests for check_index_health integration with data freshness checks."""

    def _create_mock_pattern(self, mode: str = "push", health_alerting_enabled: bool = True):
        """Helper to create a mock IndexPattern."""
        pattern = MagicMock()
        pattern.id = uuid.uuid4()
        pattern.name = f"test-{mode}-pattern"
        pattern.pattern = f"logs-{mode}-*"
        pattern.mode = mode
        pattern.timestamp_field = "@timestamp"
        pattern.health_alerting_enabled = health_alerting_enabled
        pattern.health_no_data_minutes = None
        pattern.health_error_rate_percent = None
        pattern.health_latency_ms = None
        pattern.created_at = datetime.now(UTC) - timedelta(hours=1)
        return pattern

    def _create_mock_metrics(self, pattern_id, age_minutes: int = 5):
        """Helper to create mock health metrics."""
        metrics = MagicMock()
        metrics.index_pattern_id = pattern_id
        metrics.timestamp = datetime.now(UTC) - timedelta(minutes=age_minutes)
        metrics.logs_received = 100
        metrics.logs_errored = 0
        metrics.avg_detection_latency_ms = 500
        metrics.queue_depth = 0
        return metrics

    @pytest.mark.asyncio
    async def test_pull_mode_checks_data_freshness_stale(self):
        """Pull mode pattern with stale data should create stale_data issue."""
        # Arrange
        mock_db = AsyncMock()
        mock_os_client = AsyncMock()

        # Create a pull mode pattern
        pull_pattern = self._create_mock_pattern(mode="pull")
        mock_metrics = self._create_mock_metrics(pull_pattern.id, age_minutes=2)

        # Mock database queries - use a function to handle multiple calls
        patterns_result = MagicMock()
        patterns_result.scalars.return_value.all.return_value = [pull_pattern]

        metrics_result = MagicMock()
        metrics_result.scalar_one_or_none.return_value = mock_metrics

        # Default result for suppression queries and clears
        default_result = MagicMock()
        default_result.scalar_one_or_none.return_value = None

        call_count = [0]
        def execute_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # thresholds
                return MagicMock(scalar_one_or_none=MagicMock(return_value={}))
            elif call_count[0] == 2:  # patterns query
                return patterns_result
            elif call_count[0] == 3:  # metrics query
                return metrics_result
            else:  # All other calls (suppression operations)
                return default_result

        mock_db.execute = AsyncMock(side_effect=execute_side_effect)

        # Mock stale data response from OpenSearch
        thirty_minutes_ago = datetime.now(UTC) - timedelta(minutes=30)
        mock_os_client.search = AsyncMock(return_value={
            "hits": {
                "hits": [{
                    "_source": {"@timestamp": thirty_minutes_ago.isoformat()}
                }]
            }
        })

        # Mock notification
        with patch("app.services.health_monitor.send_health_notification", new_callable=AsyncMock):
            # Act
            issues = await check_index_health(mock_db, os_client=mock_os_client)

        # Assert
        # Should have called search for data freshness check
        mock_os_client.search.assert_called_once()

        # Should have a stale_data issue
        stale_issues = [i for i in issues if i.get("condition_type") == "stale_data"]
        assert len(stale_issues) == 1
        assert "stale" in stale_issues[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_pull_mode_fresh_data_no_issue(self):
        """Pull mode pattern with fresh data should not create stale_data issue."""
        # Arrange
        mock_db = AsyncMock()
        mock_os_client = AsyncMock()

        # Create a pull mode pattern
        pull_pattern = self._create_mock_pattern(mode="pull")
        mock_metrics = self._create_mock_metrics(pull_pattern.id, age_minutes=2)

        # Mock database queries
        patterns_result = MagicMock()
        patterns_result.scalars.return_value.all.return_value = [pull_pattern]

        metrics_result = MagicMock()
        metrics_result.scalar_one_or_none.return_value = mock_metrics

        # Mock suppression clear (no existing suppression)
        suppression_result = MagicMock()
        suppression_result.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value={})),  # thresholds
            patterns_result,  # patterns query
            metrics_result,  # metrics query
            suppression_result,  # no_data clear
            suppression_result,  # error_rate clear
            suppression_result,  # latency clear
            suppression_result,  # queue_depth clear
            suppression_result,  # stale_data clear
        ])

        # Mock fresh data response from OpenSearch
        five_minutes_ago = datetime.now(UTC) - timedelta(minutes=5)
        mock_os_client.search = AsyncMock(return_value={
            "hits": {
                "hits": [{
                    "_source": {"@timestamp": five_minutes_ago.isoformat()}
                }]
            }
        })

        # Act
        issues = await check_index_health(mock_db, os_client=mock_os_client)

        # Assert
        # Should have called search for data freshness check
        mock_os_client.search.assert_called_once()

        # Should NOT have any stale_data issues
        stale_issues = [i for i in issues if i.get("condition_type") == "stale_data"]
        assert len(stale_issues) == 0

    @pytest.mark.asyncio
    async def test_push_mode_skips_data_freshness_check(self):
        """Push mode pattern should NOT check data freshness."""
        # Arrange
        mock_db = AsyncMock()
        mock_os_client = AsyncMock()

        # Create a push mode pattern
        push_pattern = self._create_mock_pattern(mode="push")
        mock_metrics = self._create_mock_metrics(push_pattern.id, age_minutes=2)

        # Mock database queries
        patterns_result = MagicMock()
        patterns_result.scalars.return_value.all.return_value = [push_pattern]

        metrics_result = MagicMock()
        metrics_result.scalar_one_or_none.return_value = mock_metrics

        # Mock suppression clear (no existing suppression)
        suppression_result = MagicMock()
        suppression_result.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value={})),  # thresholds
            patterns_result,  # patterns query
            metrics_result,  # metrics query
            suppression_result,  # no_data clear
            suppression_result,  # error_rate clear
            suppression_result,  # latency clear
            suppression_result,  # queue_depth clear
        ])

        # Act
        issues = await check_index_health(mock_db, os_client=mock_os_client)

        # Assert
        # Should NOT have called search because push mode doesn't check freshness
        mock_os_client.search.assert_not_called()

        # Should NOT have any stale_data issues
        stale_issues = [i for i in issues if i.get("condition_type") == "stale_data"]
        assert len(stale_issues) == 0

    @pytest.mark.asyncio
    async def test_pull_mode_no_data_in_index(self):
        """Pull mode pattern with no events in index should create stale_data issue."""
        # Arrange
        mock_db = AsyncMock()
        mock_os_client = AsyncMock()

        # Create a pull mode pattern
        pull_pattern = self._create_mock_pattern(mode="pull")
        mock_metrics = self._create_mock_metrics(pull_pattern.id, age_minutes=2)

        # Mock database queries - use a function to handle multiple calls
        patterns_result = MagicMock()
        patterns_result.scalars.return_value.all.return_value = [pull_pattern]

        metrics_result = MagicMock()
        metrics_result.scalar_one_or_none.return_value = mock_metrics

        # Default result for suppression queries and clears
        default_result = MagicMock()
        default_result.scalar_one_or_none.return_value = None

        call_count = [0]
        def execute_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # thresholds
                return MagicMock(scalar_one_or_none=MagicMock(return_value={}))
            elif call_count[0] == 2:  # patterns query
                return patterns_result
            elif call_count[0] == 3:  # metrics query
                return metrics_result
            else:  # All other calls (suppression operations)
                return default_result

        mock_db.execute = AsyncMock(side_effect=execute_side_effect)

        # Mock empty index response
        mock_os_client.search = AsyncMock(return_value={
            "hits": {"hits": []}
        })

        # Mock notification
        with patch("app.services.health_monitor.send_health_notification", new_callable=AsyncMock):
            # Act
            issues = await check_index_health(mock_db, os_client=mock_os_client)

        # Assert
        # Should have called search for data freshness check
        mock_os_client.search.assert_called_once()

        # Should have a stale_data issue with no_data message
        stale_issues = [i for i in issues if i.get("condition_type") == "stale_data"]
        assert len(stale_issues) == 1
        assert "no events" in stale_issues[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_os_client_obtained_only_for_pull_mode(self):
        """OpenSearch client should only be obtained when there are pull mode patterns."""
        # Arrange
        mock_db = AsyncMock()

        # Create only push mode patterns
        push_pattern = self._create_mock_pattern(mode="push")
        mock_metrics = self._create_mock_metrics(push_pattern.id, age_minutes=2)

        # Mock database queries
        patterns_result = MagicMock()
        patterns_result.scalars.return_value.all.return_value = [push_pattern]

        metrics_result = MagicMock()
        metrics_result.scalar_one_or_none.return_value = mock_metrics

        suppression_result = MagicMock()
        suppression_result.scalar_one_or_none.return_value = None

        mock_db.execute = AsyncMock(side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value={})),  # thresholds
            patterns_result,  # patterns query
            metrics_result,  # metrics query
            suppression_result,  # no_data clear
            suppression_result,  # error_rate clear
            suppression_result,  # latency clear
            suppression_result,  # queue_depth clear
        ])

        # Mock get_client_from_settings to verify it's not called
        with patch("app.services.health_monitor.get_client_from_settings", new_callable=AsyncMock) as mock_get_client:
            # Act
            await check_index_health(mock_db)

            # Assert - should not try to get OpenSearch client for push-only patterns
            mock_get_client.assert_not_called()
