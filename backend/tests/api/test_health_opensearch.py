"""Tests for OpenSearch health endpoint."""

from unittest.mock import patch, MagicMock

import pytest

from app.core.circuit_breaker import CircuitState


@pytest.mark.asyncio
async def test_opensearch_health_returns_state(authenticated_client):
    """Health endpoint returns circuit breaker state."""
    response = await authenticated_client.get("/api/health/opensearch")
    assert response.status_code == 200
    data = response.json()
    assert "available" in data
    assert "circuit_state" in data
    assert data["circuit_state"] in ["closed", "open", "half_open"]


@pytest.mark.asyncio
async def test_opensearch_health_open_circuit(authenticated_client):
    """Health endpoint reports unavailable when circuit is open."""
    mock_instance = MagicMock()
    mock_instance.get_state.return_value = CircuitState.OPEN
    mock_instance.get_failure_count.return_value = 3
    mock_instance._last_failure_time = 1234567890.0

    with patch("app.api.health.get_circuit_breaker", return_value=mock_instance):
        response = await authenticated_client.get("/api/health/opensearch")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is False
        assert data["circuit_state"] == "open"
        assert data["failure_count"] == 3
