"""Tests for automatic MISP sighting feedback (Feature D)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ti import misp_auto_sighting as mas
from app.services.ti.misp_feedback import SightingResult


def _alert(*uuids):
    return {
        "alert_id": "a",
        "ioc_matches": [{"misp_attribute_uuid": u} for u in uuids],
    }


def test_extract_uuids_dedups_and_skips_blanks():
    alerts = [
        _alert("u1", "u2"),
        _alert("u2"),  # duplicate across alerts
        {"ioc_matches": [{"value": "1.2.3.4"}]},  # no uuid
        {"ioc_matches": None},
        {},
    ]
    assert mas.extract_misp_attribute_uuids(alerts) == {"u1", "u2"}


@pytest.mark.asyncio
async def test_disabled_is_noop():
    db = MagicMock()
    with (
        patch.object(mas, "get_setting", new=AsyncMock(return_value={"enabled": False})),
        patch(
            "app.api.misp_feedback.create_feedback_service",
            new=AsyncMock(),
        ) as build,
    ):
        n = await mas.record_sightings_for_alerts(db, [_alert("u1")])
    assert n == 0
    build.assert_not_called()


@pytest.mark.asyncio
async def test_no_uuids_is_noop():
    db = MagicMock()
    with patch.object(
        mas, "get_setting", new=AsyncMock(return_value={"enabled": True})
    ):
        n = await mas.record_sightings_for_alerts(
            db, [{"ioc_matches": [{"value": "x"}]}]
        )
    assert n == 0


@pytest.mark.asyncio
async def test_records_sighting_when_enabled():
    db = MagicMock()

    service = MagicMock()
    service.record_sighting = AsyncMock(
        return_value=SightingResult(success=True, sighting_id="42")
    )
    service._client = MagicMock()
    service._client.aclose = AsyncMock()

    redis = AsyncMock()
    redis.set = AsyncMock(return_value=True)  # claim succeeds

    with (
        patch.object(mas, "get_setting", new=AsyncMock(return_value={"enabled": True})),
        patch(
            "app.api.misp_feedback.create_feedback_service",
            new=AsyncMock(return_value=service),
        ),
        patch.object(mas, "get_redis", new=AsyncMock(return_value=redis)),
        patch.object(mas, "audit_log", new=AsyncMock()) as audit,
    ):
        n = await mas.record_sightings_for_alerts(db, [_alert("u1")])

    assert n == 1
    service.record_sighting.assert_awaited_once()
    _, kwargs = service.record_sighting.call_args
    assert kwargs["attribute_uuid"] == "u1"
    assert kwargs["source"] == "CHAD"
    assert kwargs["sighting_type"] == 0
    service._client.aclose.assert_awaited_once()
    audit.assert_awaited_once()  # system-actor audit entry


@pytest.mark.asyncio
async def test_dedup_skips_already_claimed():
    db = MagicMock()
    service = MagicMock()
    service.record_sighting = AsyncMock(
        return_value=SightingResult(success=True, sighting_id="1")
    )
    service._client = MagicMock()
    service._client.aclose = AsyncMock()

    redis = AsyncMock()
    redis.set = AsyncMock(return_value=None)  # NX claim fails → already sighted

    with (
        patch.object(mas, "get_setting", new=AsyncMock(return_value={"enabled": True})),
        patch(
            "app.api.misp_feedback.create_feedback_service",
            new=AsyncMock(return_value=service),
        ),
        patch.object(mas, "get_redis", new=AsyncMock(return_value=redis)),
        patch.object(mas, "audit_log", new=AsyncMock()),
    ):
        n = await mas.record_sightings_for_alerts(db, [_alert("u1")])

    assert n == 0
    service.record_sighting.assert_not_awaited()


@pytest.mark.asyncio
async def test_misp_not_configured_is_silent():
    db = MagicMock()
    with (
        patch.object(mas, "get_setting", new=AsyncMock(return_value={"enabled": True})),
        patch(
            "app.api.misp_feedback.create_feedback_service",
            new=AsyncMock(side_effect=RuntimeError("not configured")),
        ),
    ):
        n = await mas.record_sightings_for_alerts(db, [_alert("u1")])
    assert n == 0
