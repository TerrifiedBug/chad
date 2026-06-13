"""Tests for alert-storm notification throttling."""

import pytest


class FakeRedis:
    def __init__(self):
        self.store: dict[str, int] = {}

    async def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key, ttl):
        return True


@pytest.mark.asyncio
async def test_throttle_caps_notifications_per_window(monkeypatch):
    import app.core.redis as redis_mod
    from app.services.notification import (
        NOTIFICATION_THROTTLE_MAX,
        _notification_allowed,
    )

    fake = FakeRedis()

    async def fake_get_redis():
        return fake

    monkeypatch.setattr(redis_mod, "get_redis", fake_get_redis)

    allowed_count = 0
    for _ in range(NOTIFICATION_THROTTLE_MAX + 5):
        allowed, _count = await _notification_allowed("wh:1:Noisy Rule")
        if allowed:
            allowed_count += 1

    # Only the first MAX notifications in the window are allowed through.
    assert allowed_count == NOTIFICATION_THROTTLE_MAX


@pytest.mark.asyncio
async def test_throttle_is_per_destination_and_rule(monkeypatch):
    import app.core.redis as redis_mod
    from app.services.notification import _notification_allowed

    fake = FakeRedis()

    async def fake_get_redis():
        return fake

    monkeypatch.setattr(redis_mod, "get_redis", fake_get_redis)

    # Different rule keys have independent budgets.
    allowed_a, _ = await _notification_allowed("wh:1:Rule A")
    allowed_b, _ = await _notification_allowed("wh:1:Rule B")
    assert allowed_a is True
    assert allowed_b is True


@pytest.mark.asyncio
async def test_throttle_fails_open_on_redis_error(monkeypatch):
    import app.core.redis as redis_mod
    from app.services.notification import _notification_allowed

    async def boom():
        raise Exception("redis down")

    monkeypatch.setattr(redis_mod, "get_redis", boom)

    allowed, count = await _notification_allowed("wh:1:rule")
    assert allowed is True
    assert count == 0
