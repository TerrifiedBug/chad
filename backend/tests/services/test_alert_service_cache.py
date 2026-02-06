# backend/tests/services/test_alert_service_cache.py
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_get_alerts_returns_cached_on_os_failure():
    """When OpenSearch fails but cache has data, return cached data."""
    from app.services.alerts import AlertService
    from app.services.alert_cache import AlertCache

    os_client = MagicMock()
    os_client.search = MagicMock(side_effect=Exception("Connection refused"))

    cached_data = {"total": 2, "alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}]}
    mock_cache = AsyncMock(spec=AlertCache)
    mock_cache.get_alerts = AsyncMock(return_value=cached_data)

    service = AlertService(os_client)
    result = await service.get_alerts_cached(cache=mock_cache, status="new")

    assert result["total"] == 2
    assert result["cached"] is True
    assert result["opensearch_available"] is False


@pytest.mark.asyncio
async def test_get_alerts_caches_fresh_result():
    """Fresh OpenSearch result should be cached."""
    from app.services.alerts import AlertService
    from app.services.alert_cache import AlertCache

    os_result = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_source": {"alert_id": "a1", "rule_id": "test"}}],
        }
    }
    os_client = MagicMock()
    os_client.search = MagicMock(return_value=os_result)

    mock_cache = AsyncMock(spec=AlertCache)
    mock_cache.get_alerts = AsyncMock(return_value=None)

    service = AlertService(os_client)
    result = await service.get_alerts_cached(cache=mock_cache, status="new")

    assert result["total"] == 1
    assert result["cached"] is False
    assert result["opensearch_available"] is True
    mock_cache.set_alerts.assert_called_once()


@pytest.mark.asyncio
async def test_get_alerts_no_cache_no_os_raises():
    """When both cache and OpenSearch fail, raise error."""
    from app.core.exceptions import OpenSearchUnavailableError
    from app.services.alerts import AlertService
    from app.services.alert_cache import AlertCache

    os_client = MagicMock()
    os_client.search = MagicMock(side_effect=Exception("Connection refused"))

    mock_cache = AsyncMock(spec=AlertCache)
    mock_cache.get_alerts = AsyncMock(return_value=None)

    service = AlertService(os_client)
    with pytest.raises(OpenSearchUnavailableError):
        await service.get_alerts_cached(cache=mock_cache, status="new")
