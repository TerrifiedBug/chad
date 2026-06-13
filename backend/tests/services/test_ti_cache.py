"""Tests for the TI enrichment result cache."""

from unittest.mock import AsyncMock, MagicMock

import pytest


class FakeRedis:
    """Minimal in-memory async Redis stand-in for get/set."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value


def test_enrichment_result_round_trips_through_dict():
    """to_dict -> from_dict -> to_dict must be stable so cached values survive."""
    from app.services.ti.base import TIIndicatorType, TILookupResult, TIRiskLevel
    from app.services.ti.manager import TIEnrichmentResult

    result = TIEnrichmentResult(
        indicator="1.2.3.4",
        indicator_type=TIIndicatorType.IP,
        overall_risk_level=TIRiskLevel.HIGH,
        overall_risk_score=90.0,
        highest_risk_source="fake",
        sources_queried=2,
        sources_with_results=1,
        sources_with_detections=1,
        all_categories=["malware"],
        all_tags=["botnet"],
        source_results=[
            TILookupResult(
                source="fake",
                indicator="1.2.3.4",
                indicator_type=TIIndicatorType.IP,
                success=True,
                risk_level=TIRiskLevel.HIGH,
                risk_score=90.0,
                malicious_count=5,
                total_count=10,
                categories=["malware"],
                tags=["botnet"],
            )
        ],
    )

    as_dict = result.to_dict()
    rebuilt = TIEnrichmentResult.from_dict(as_dict)

    assert rebuilt.to_dict() == as_dict
    assert rebuilt.overall_risk_level == TIRiskLevel.HIGH
    assert rebuilt.source_results[0].indicator_type == TIIndicatorType.IP


@pytest.mark.asyncio
async def test_enrich_serves_second_lookup_from_cache(monkeypatch):
    """The same indicator must not re-query providers within the TTL."""
    from app.services.ti import manager as manager_module
    from app.services.ti.base import TIIndicatorType, TILookupResult, TIRiskLevel
    from app.services.ti.manager import TIEnrichmentManager

    fake_redis = FakeRedis()

    async def fake_get_redis():
        return fake_redis

    monkeypatch.setattr(manager_module, "get_redis", fake_get_redis)

    manager = TIEnrichmentManager()
    client = MagicMock()
    client.source_name = "fake"
    client.supported_types = [TIIndicatorType.IP]
    client.lookup = AsyncMock(
        return_value=TILookupResult(
            source="fake",
            indicator="1.2.3.4",
            indicator_type=TIIndicatorType.IP,
            success=True,
            risk_level=TIRiskLevel.HIGH,
            risk_score=90.0,
            malicious_count=5,
        )
    )
    manager._clients = {"fake": client}

    first = await manager.enrich("1.2.3.4", TIIndicatorType.IP)
    second = await manager.enrich("1.2.3.4", TIIndicatorType.IP)

    # Provider queried exactly once; the second call is served from cache.
    assert client.lookup.await_count == 1
    assert second.sources_with_results == 1
    assert second.overall_risk_level == TIRiskLevel.HIGH
    assert second.to_dict() == first.to_dict()


@pytest.mark.asyncio
async def test_enrich_does_not_cache_all_failure(monkeypatch):
    """An all-failure lookup must not be cached (would suppress later detections)."""
    from app.services.ti import manager as manager_module
    from app.services.ti.base import TIIndicatorType, TILookupResult
    from app.services.ti.manager import TIEnrichmentManager

    fake_redis = FakeRedis()

    async def fake_get_redis():
        return fake_redis

    monkeypatch.setattr(manager_module, "get_redis", fake_get_redis)

    manager = TIEnrichmentManager()
    client = MagicMock()
    client.source_name = "fake"
    client.supported_types = [TIIndicatorType.IP]
    client.lookup = AsyncMock(
        return_value=TILookupResult(
            source="fake",
            indicator="9.9.9.9",
            indicator_type=TIIndicatorType.IP,
            success=False,
            error="quota exceeded",
        )
    )
    manager._clients = {"fake": client}

    await manager.enrich("9.9.9.9", TIIndicatorType.IP)
    await manager.enrich("9.9.9.9", TIIndicatorType.IP)

    # No authoritative response, so nothing cached -> provider queried each time.
    assert client.lookup.await_count == 2
    assert fake_redis.store == {}
