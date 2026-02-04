"""Tests for enrichment webhook service."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.services.enrichment_webhook import (
    _extract_field_value,
    _get_cached_enrichment,
    _get_circuit_state,
    _is_circuit_open,
    _record_failure,
    _record_success,
    _set_cached_enrichment,
    call_enrichment_webhook,
)


class TestExtractFieldValue:
    """Tests for field extraction helper."""

    def test_simple_key(self):
        """Extract simple top-level key."""
        doc = {"user": "admin"}
        assert _extract_field_value(doc, "user") == "admin"

    def test_nested_key(self):
        """Extract nested key using dot notation."""
        doc = {"user": {"name": "admin", "email": "admin@example.com"}}
        assert _extract_field_value(doc, "user.name") == "admin"

    def test_deeply_nested(self):
        """Extract deeply nested key."""
        doc = {"level1": {"level2": {"level3": {"value": "deep"}}}}
        assert _extract_field_value(doc, "level1.level2.level3.value") == "deep"

    def test_missing_key(self):
        """Return None for missing key."""
        doc = {"user": "admin"}
        assert _extract_field_value(doc, "missing") is None

    def test_missing_nested_key(self):
        """Return None for missing nested key."""
        doc = {"user": {"name": "admin"}}
        assert _extract_field_value(doc, "user.missing") is None

    def test_partial_path_missing(self):
        """Return None when intermediate path is missing."""
        doc = {"user": "admin"}
        assert _extract_field_value(doc, "user.name.first") is None

    def test_non_dict_intermediate(self):
        """Return None when intermediate value is not a dict."""
        doc = {"user": "admin"}
        assert _extract_field_value(doc, "user.name") is None


class TestCircuitBreaker:
    """Tests for circuit breaker functionality."""

    @pytest.mark.asyncio
    async def test_circuit_starts_closed(self):
        """New circuits start in closed state."""
        import uuid

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            state = await _get_circuit_state(uuid.uuid4())
            assert state["state"] == "closed"
            assert state["failures"] == 0

    @pytest.mark.asyncio
    async def test_record_failure_increments_count(self):
        """Recording failure increments failure count."""
        import json
        import uuid

        webhook_id = uuid.uuid4()
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps({
            "state": "closed",
            "failures": 2,
            "last_failure": None,
        }))
        mock_redis.setex = AsyncMock()

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            await _record_failure(webhook_id)

            # Verify state was updated
            call_args = mock_redis.setex.call_args
            saved_state = json.loads(call_args[0][2])
            assert saved_state["failures"] == 3
            assert saved_state["state"] == "closed"

    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold(self):
        """Circuit opens after failure threshold reached."""
        import json
        import uuid

        webhook_id = uuid.uuid4()
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps({
            "state": "closed",
            "failures": 4,  # One more failure will open circuit
            "last_failure": None,
        }))
        mock_redis.setex = AsyncMock()

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            await _record_failure(webhook_id)

            call_args = mock_redis.setex.call_args
            saved_state = json.loads(call_args[0][2])
            assert saved_state["failures"] == 5
            assert saved_state["state"] == "open"

    @pytest.mark.asyncio
    async def test_record_success_resets_circuit(self):
        """Recording success closes circuit and resets failures."""
        import json
        import uuid

        webhook_id = uuid.uuid4()
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            await _record_success(webhook_id)

            call_args = mock_redis.setex.call_args
            saved_state = json.loads(call_args[0][2])
            assert saved_state["state"] == "closed"
            assert saved_state["failures"] == 0

    @pytest.mark.asyncio
    async def test_is_circuit_open_returns_false_when_closed(self):
        """Circuit is not open when in closed state."""
        import json
        import uuid

        webhook_id = uuid.uuid4()
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps({
            "state": "closed",
            "failures": 0,
            "last_failure": None,
        }))

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            is_open = await _is_circuit_open(webhook_id)
            assert is_open is False

    @pytest.mark.asyncio
    async def test_is_circuit_open_returns_true_when_open(self):
        """Circuit is open when in open state within recovery timeout."""
        import json
        import uuid
        from datetime import UTC, datetime

        webhook_id = uuid.uuid4()
        recent_failure = datetime.now(UTC).isoformat()
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps({
            "state": "open",
            "failures": 5,
            "last_failure": recent_failure,
        }))

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            is_open = await _is_circuit_open(webhook_id)
            assert is_open is True


class TestCaching:
    """Tests for enrichment caching."""

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self):
        """Cache miss returns None."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            result = await _get_cached_enrichment("test_ns", "lookup_value")
            assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit_returns_data(self):
        """Cache hit returns stored data."""
        import json

        cached_data = {"user_name": "John Doe", "department": "Engineering"}
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps(cached_data))

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            result = await _get_cached_enrichment("test_ns", "lookup_value")
            assert result == cached_data

    @pytest.mark.asyncio
    async def test_set_cache_with_ttl(self):
        """Cache is set with correct TTL."""
        import json

        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()

        data = {"result": "test"}
        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            await _set_cached_enrichment("test_ns", "lookup_value", data, 300)

            mock_redis.setex.assert_called_once()
            call_args = mock_redis.setex.call_args[0]
            assert call_args[0] == "enrichment:test_ns:lookup_value"
            assert call_args[1] == 300
            assert json.loads(call_args[2]) == data

    @pytest.mark.asyncio
    async def test_set_cache_zero_ttl_skipped(self):
        """Cache is not set when TTL is zero."""
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()

        data = {"result": "test"}
        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            await _set_cached_enrichment("test_ns", "lookup_value", data, 0)

            mock_redis.setex.assert_not_called()


class TestCallEnrichmentWebhook:
    """Tests for calling enrichment webhooks."""

    @pytest.mark.asyncio
    async def test_call_webhook_cache_hit(self):
        """Return cached data if available."""
        import json
        import uuid

        webhook = AsyncMock()
        webhook.id = uuid.uuid4()
        webhook.namespace = "test_ns"
        webhook.cache_ttl_seconds = 300

        cached_data = {"user_name": "Cached User"}
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps(cached_data))

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            namespace, data, status = await call_enrichment_webhook(
                webhook=webhook,
                field_to_send="user.email",
                alert_id="alert-1",
                rule_id="rule-1",
                rule_title="Test Rule",
                severity="medium",
                log_document={"user": {"email": "user@example.com"}},
            )

            assert namespace == "test_ns"
            assert data == cached_data
            assert status["status"] == "success"
            assert status["source"] == "cache"

    @pytest.mark.asyncio
    async def test_call_webhook_circuit_open(self):
        """Return error when circuit is open."""
        import json
        import uuid
        from datetime import UTC, datetime

        webhook = AsyncMock()
        webhook.id = uuid.uuid4()
        webhook.namespace = "test_ns"
        webhook.url = "https://api.example.com/enrich"
        webhook.cache_ttl_seconds = 0  # No caching

        recent_failure = datetime.now(UTC).isoformat()
        mock_redis = AsyncMock()
        # Circuit state returns open
        mock_redis.get = AsyncMock(return_value=json.dumps({
            "state": "open",
            "failures": 5,
            "last_failure": recent_failure,
        }))

        with patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis):
            namespace, data, status = await call_enrichment_webhook(
                webhook=webhook,
                field_to_send="user.email",
                alert_id="alert-1",
                rule_id="rule-1",
                rule_title="Test Rule",
                severity="medium",
                log_document={"user": {"email": "user@example.com"}},
            )

            assert namespace == "test_ns"
            assert data is None
            assert status["status"] == "circuit_open"

    @pytest.mark.asyncio
    async def test_call_webhook_success(self):
        """Successfully call webhook and return enrichment data."""
        import json
        import uuid

        webhook = AsyncMock()
        webhook.id = uuid.uuid4()
        webhook.namespace = "test_ns"
        webhook.url = "https://api.example.com/enrich"
        webhook.method = "POST"
        webhook.header_name = None
        webhook.header_value_encrypted = None
        webhook.timeout_seconds = 30
        webhook.max_concurrent_calls = 5
        webhook.cache_ttl_seconds = 0  # No caching

        enrichment_response = {"user_name": "John Doe", "department": "Engineering"}

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=[
            None,  # No cache
            json.dumps({"state": "closed", "failures": 0, "last_failure": None}),
        ])
        mock_redis.setex = AsyncMock()

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: enrichment_response

        sanitize_result = ("https://api.example.com/enrich", None)
        with (
            patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis),
            patch("app.services.enrichment_webhook.sanitize_webhook_url", return_value=sanitize_result),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            namespace, data, status = await call_enrichment_webhook(
                webhook=webhook,
                field_to_send="user.email",
                alert_id="alert-1",
                rule_id="rule-1",
                rule_title="Test Rule",
                severity="medium",
                log_document={"user": {"email": "user@example.com"}},
            )

            assert namespace == "test_ns"
            assert data == enrichment_response
            assert status["status"] == "success"

    @pytest.mark.asyncio
    async def test_call_webhook_timeout(self):
        """Handle webhook timeout gracefully."""
        import json
        import uuid

        webhook = AsyncMock()
        webhook.id = uuid.uuid4()
        webhook.namespace = "test_ns"
        webhook.url = "https://api.example.com/enrich"
        webhook.method = "POST"
        webhook.header_name = None
        webhook.header_value_encrypted = None
        webhook.timeout_seconds = 5
        webhook.max_concurrent_calls = 5
        webhook.cache_ttl_seconds = 0

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=[
            None,  # No cache
            json.dumps({"state": "closed", "failures": 0, "last_failure": None}),
        ])
        mock_redis.setex = AsyncMock()

        sanitize_result_timeout = ("https://api.example.com/enrich", None)
        with (
            patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis),
            patch("app.services.enrichment_webhook.sanitize_webhook_url", return_value=sanitize_result_timeout),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            namespace, data, status = await call_enrichment_webhook(
                webhook=webhook,
                field_to_send="user.email",
                alert_id="alert-1",
                rule_id="rule-1",
                rule_title="Test Rule",
                severity="medium",
                log_document={"user": {"email": "user@example.com"}},
            )

            assert namespace == "test_ns"
            assert data is None
            assert status["status"] == "timeout"
            assert "timed out" in status["error"]

    @pytest.mark.asyncio
    async def test_call_webhook_ssrf_blocked(self):
        """Return error when URL is blocked by SSRF protection."""
        import json
        import uuid

        webhook = AsyncMock()
        webhook.id = uuid.uuid4()
        webhook.namespace = "test_ns"
        webhook.url = "http://127.0.0.1/internal"
        webhook.cache_ttl_seconds = 0

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=[
            None,  # No cache
            json.dumps({"state": "closed", "failures": 0, "last_failure": None}),
        ])

        ssrf_error = (None, "SSRF protection: localhost blocked")
        with (
            patch("app.services.enrichment_webhook.get_redis", return_value=mock_redis),
            patch("app.services.enrichment_webhook.sanitize_webhook_url", return_value=ssrf_error),
        ):
            namespace, data, status = await call_enrichment_webhook(
                webhook=webhook,
                field_to_send="user.email",
                alert_id="alert-1",
                rule_id="rule-1",
                rule_title="Test Rule",
                severity="medium",
                log_document={"user": {"email": "user@example.com"}},
            )

            assert namespace == "test_ns"
            assert data is None
            assert status["status"] == "failed"
            assert "SSRF" in status["error"]
