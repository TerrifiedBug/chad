"""Tests for TI enrichment cache refinements (Feature E).

Covers the provider-fingerprint cache key, the Redis flush, and the
runtime-tunable TTL resolution used by the enrichment manager singleton.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti.base import TIIndicatorType
from app.services.ti.manager import (
    _TI_CACHE_PREFIX,
    DEFAULT_CACHE_TTL_SECONDS,
    TIEnrichmentManager,
)


class _FakeRedis:
    """Minimal async Redis stub supporting scan_iter + delete."""

    def __init__(self, keys):
        self._keys = list(keys)
        self.deleted: list[str] = []

    async def scan_iter(self, match=None, count=None):
        for key in list(self._keys):
            yield key

    async def delete(self, key):
        self.deleted.append(key)
        return 1


def test_cache_version_changes_with_provider_set():
    """Enabling/disabling a provider must change the cache fingerprint."""
    manager = TIEnrichmentManager()

    manager._clients = {"virustotal": object()}
    v1 = manager._compute_cache_version()

    manager._clients = {"virustotal": object(), "abuseipdb": object()}
    v2 = manager._compute_cache_version()

    assert v1 != v2
    # Stable + order-independent for the same set.
    manager._clients = {"abuseipdb": object(), "virustotal": object()}
    assert manager._compute_cache_version() == v2


def test_cache_key_embeds_version():
    """The cache key must carry the provider fingerprint segment."""
    manager = TIEnrichmentManager()
    manager._cache_version = "abcd1234"

    key = manager._cache_key("1.2.3.4", TIIndicatorType.IP)

    assert key == f"{_TI_CACHE_PREFIX}:abcd1234:ip:1.2.3.4"


def test_cache_key_differs_across_versions():
    """Same indicator under different provider sets → different keys."""
    manager = TIEnrichmentManager()

    manager._cache_version = "aaaa"
    old = manager._cache_key("8.8.8.8", TIIndicatorType.IP)
    manager._cache_version = "bbbb"
    new = manager._cache_key("8.8.8.8", TIIndicatorType.IP)

    assert old != new


@pytest.mark.asyncio
async def test_flush_cache_scans_and_deletes():
    """flush_cache() deletes every chad:ti:cache:* key, fail-open."""
    fake = _FakeRedis(
        [f"{_TI_CACHE_PREFIX}:v:ip:1.1.1.1", f"{_TI_CACHE_PREFIX}:v:ip:2.2.2.2"]
    )
    manager = TIEnrichmentManager()

    with patch(
        "app.services.ti.manager.get_redis", new=AsyncMock(return_value=fake)
    ):
        deleted = await manager.flush_cache()

    assert deleted == 2
    assert len(fake.deleted) == 2


@pytest.mark.asyncio
async def test_flush_cache_failopen_on_redis_error():
    """A Redis error during flush returns 0 rather than raising."""
    manager = TIEnrichmentManager()
    with patch(
        "app.services.ti.manager.get_redis",
        new=AsyncMock(side_effect=RuntimeError("redis down")),
    ):
        assert await manager.flush_cache() == 0


@pytest.mark.asyncio
async def test_resolve_cache_ttl_reads_setting():
    """_resolve_cache_ttl honours a configured ti_cache setting."""
    from app.services import enrichment

    db = MagicMock()
    with patch.object(
        enrichment, "get_setting", new=AsyncMock(return_value={"cache_ttl_seconds": 120})
    ):
        assert await enrichment._resolve_cache_ttl(db) == 120


@pytest.mark.asyncio
async def test_resolve_cache_ttl_defaults_when_unset():
    """Missing/invalid setting falls back to the default TTL."""
    from app.services import enrichment

    db = MagicMock()
    with patch.object(enrichment, "get_setting", new=AsyncMock(return_value=None)):
        assert await enrichment._resolve_cache_ttl(db) == DEFAULT_CACHE_TTL_SECONDS

    with patch.object(
        enrichment, "get_setting", new=AsyncMock(return_value={"cache_ttl_seconds": "bad"})
    ):
        assert await enrichment._resolve_cache_ttl(db) == DEFAULT_CACHE_TTL_SECONDS


@pytest.mark.asyncio
async def test_reinitialize_flushes_cache():
    """reinitialize_ti_manager flushes the result cache on config change."""
    from app.services import enrichment

    existing = MagicMock()
    existing.flush_cache = AsyncMock(return_value=3)
    existing.close = AsyncMock()

    new_manager = MagicMock()
    new_manager.initialize = AsyncMock()

    db = MagicMock()
    with (
        patch.object(enrichment, "_ti_manager", existing),
        patch.object(
            enrichment, "_build_ti_manager", new=AsyncMock(return_value=new_manager)
        ),
    ):
        await enrichment.reinitialize_ti_manager(db)

    existing.flush_cache.assert_awaited_once()
    existing.close.assert_awaited_once()
