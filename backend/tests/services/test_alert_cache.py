"""Tests for Redis alert cache layer."""

import json
from unittest.mock import AsyncMock

import pytest

from app.services.alert_cache import AlertCache


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    redis.keys = AsyncMock(return_value=[])
    return redis


@pytest.fixture
def cache(mock_redis):
    return AlertCache(mock_redis, ttl=30)


@pytest.mark.asyncio
async def test_cache_miss_returns_none(cache):
    result = await cache.get_alerts(status="new", limit=100, offset=0)
    assert result is None


@pytest.mark.asyncio
async def test_cache_hit_returns_data(cache, mock_redis):
    cached = {"total": 5, "alerts": [{"alert_id": "abc"}]}
    mock_redis.get = AsyncMock(return_value=json.dumps(cached))
    result = await cache.get_alerts(status="new", limit=100, offset=0)
    assert result["total"] == 5
    assert len(result["alerts"]) == 1


@pytest.mark.asyncio
async def test_set_alerts_stores_with_ttl(cache, mock_redis):
    data = {"total": 1, "alerts": []}
    await cache.set_alerts(data, status="new", limit=100, offset=0)
    mock_redis.setex.assert_called_once()
    args = mock_redis.setex.call_args
    assert args[0][1] == 30  # TTL


@pytest.mark.asyncio
async def test_invalidate_deletes_matching_keys(cache, mock_redis):
    mock_redis.keys = AsyncMock(return_value=["alerts:list:abc", "alerts:list:def"])
    await cache.invalidate()
    assert mock_redis.delete.call_count == 2


@pytest.mark.asyncio
async def test_cache_key_deterministic(cache):
    key1 = cache._build_key(status="new", limit=100, offset=0)
    key2 = cache._build_key(status="new", limit=100, offset=0)
    assert key1 == key2


@pytest.mark.asyncio
async def test_cache_key_differs_for_different_params(cache):
    key1 = cache._build_key(status="new", limit=100, offset=0)
    key2 = cache._build_key(status="resolved", limit=100, offset=0)
    assert key1 != key2
