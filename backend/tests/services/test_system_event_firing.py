"""Tests that previously-dead system events now fire send_system_notification."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scheduler import SchedulerService


@pytest.fixture
def scheduler_service():
    """Create scheduler service for testing."""
    return SchedulerService()


@pytest.mark.asyncio
async def test_misp_failure_emits_listed_sync_failed_event(scheduler_service):
    """After 3 consecutive failures MISP must emit a LISTED event name.

    Regression: it previously emitted 'misp_sync_failed', which is absent from
    SYSTEM_EVENT_TYPES, so the notification was silently dropped.
    """
    session = MagicMock()

    redis = AsyncMock()
    # Two prior failures already recorded -> this call makes it the 3rd (threshold).
    redis.get.return_value = "2"

    with patch("app.services.scheduler.get_redis", new_callable=AsyncMock) as mock_get_redis, \
         patch("app.services.notification.send_system_notification", new_callable=AsyncMock) as mock_notify:
        mock_get_redis.return_value = redis

        await scheduler_service._track_misp_sync_failure(session, "MISP connection timeout")

    mock_notify.assert_called_once()
    args, _ = mock_notify.call_args
    # args == (session, event_type, payload)
    assert args[1] == "sync_failed", f"expected listed event 'sync_failed', got {args[1]!r}"
    assert args[2]["sync_type"] == "misp"
    assert args[2]["consecutive_failures"] == 3
    assert args[2]["error"] == "MISP connection timeout"


@pytest.mark.asyncio
async def test_attack_sync_failure_emits_attack_sync_failed(scheduler_service):
    """A failed ATT&CK sync must additionally fire the listed attack_sync_failed event."""
    session = AsyncMock()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

    result = MagicMock()
    result.success = False
    result.error = "feed unreachable"
    result.message = "sync failed"

    sync_service = MagicMock()
    sync_service.sync = AsyncMock(return_value=result)

    with patch.object(scheduler_service, "_get_session", new_callable=AsyncMock) as mock_sess, \
         patch("app.services.attack_sync.attack_sync_service", sync_service), \
         patch("app.services.audit.audit_log", new_callable=AsyncMock), \
         patch("app.services.notification.send_system_notification", new_callable=AsyncMock) as mock_notify:
        mock_sess.return_value = session

        await scheduler_service._execute_attack_sync()

    events = [c.args[1] for c in mock_notify.call_args_list]
    assert "attack_sync_failed" in events, f"attack_sync_failed not fired; got {events}"


@pytest.mark.asyncio
async def test_sigmahq_sync_failure_emits_sigmahq_sync_failed(scheduler_service):
    """A failed SigmaHQ sync must additionally fire the listed sigmahq_sync_failed event."""
    session = AsyncMock()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

    result = MagicMock()
    result.success = False
    result.message = "clone failed"
    result.error = "git timeout"
    result.rule_counts = {}

    sigmahq_service = MagicMock()
    sigmahq_service.is_repo_cloned.return_value = False
    sigmahq_service.clone_repo.return_value = result

    with patch.object(scheduler_service, "_get_session", new_callable=AsyncMock) as mock_sess, \
         patch("app.services.sigmahq.sigmahq_service", sigmahq_service), \
         patch("app.services.audit.audit_log", new_callable=AsyncMock), \
         patch("app.services.notification.send_system_notification", new_callable=AsyncMock) as mock_notify:
        mock_sess.return_value = session

        await scheduler_service._execute_sigmahq_sync()

    events = [c.args[1] for c in mock_notify.call_args_list]
    assert "sigmahq_sync_failed" in events, f"sigmahq_sync_failed not fired; got {events}"


@pytest.mark.asyncio
async def test_geoip_soft_failure_emits_maxmind_update_failed(scheduler_service):
    """When download_database returns success=False, fire maxmind_update_failed."""
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=[
            MagicMock(key="geoip_enabled", value=True),
            MagicMock(key="geoip_license_key", value="enc-key"),
        ])
    )

    geoip_service = MagicMock()
    geoip_service.download_database = AsyncMock(return_value={"success": False, "error": "Invalid license key"})

    with patch.object(scheduler_service, "_get_session", new_callable=AsyncMock) as mock_sess, \
         patch("app.services.geoip.geoip_service", geoip_service), \
         patch("app.services.scheduler.decrypt", return_value="plain-key"), \
         patch("app.services.notification.send_system_notification", new_callable=AsyncMock) as mock_notify:
        mock_sess.return_value = session

        await scheduler_service._execute_geoip_update()

    events = [c.args[1] for c in mock_notify.call_args_list]
    assert "maxmind_update_failed" in events, f"maxmind_update_failed not fired; got {events}"
    payload = next(c.args[2] for c in mock_notify.call_args_list if c.args[1] == "maxmind_update_failed")
    assert payload["error"] == "Invalid license key"


@pytest.mark.asyncio
async def test_geoip_exception_emits_maxmind_update_failed(scheduler_service):
    """When download_database raises, fire maxmind_update_failed in the except handler."""
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=[
            MagicMock(key="geoip_enabled", value=True),
            MagicMock(key="geoip_license_key", value="enc-key"),
        ])
    )

    geoip_service = MagicMock()
    geoip_service.download_database = AsyncMock(side_effect=RuntimeError("disk full"))

    with patch.object(scheduler_service, "_get_session", new_callable=AsyncMock) as mock_sess, \
         patch("app.services.geoip.geoip_service", geoip_service), \
         patch("app.services.scheduler.decrypt", return_value="plain-key"), \
         patch("app.services.scheduler.system_log_service") as mock_sys_log, \
         patch("app.services.notification.send_system_notification", new_callable=AsyncMock) as mock_notify:
        mock_sess.return_value = session
        mock_sys_log.log_error = AsyncMock()

        await scheduler_service._execute_geoip_update()

    events = [c.args[1] for c in mock_notify.call_args_list]
    assert "maxmind_update_failed" in events, f"maxmind_update_failed not fired; got {events}"
