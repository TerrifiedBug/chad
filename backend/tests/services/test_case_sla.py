"""Unit tests for the case SLA breach scan (writes sla_due_at / sla_breached)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.case import Case, CaseStatus
from app.services.sla import save_sla_policy, scan_case_sla_breaches


def _make_case(*, severity: str, created_at: datetime, status: str = CaseStatus.OPEN.value) -> Case:
    return Case(
        id=uuid.uuid4(),
        number=int(datetime.now().timestamp() * 1000) % 1_000_000_000 + uuid.uuid4().int % 1000,
        title="SLA case",
        severity=severity,
        status=status,
        created_at=created_at,
    )


@pytest.mark.asyncio
async def test_scan_noop_when_policy_disabled(db_session):
    await save_sla_policy(db_session, {"enabled": False})
    await db_session.commit()
    case = _make_case(severity="high", created_at=datetime.now(UTC) - timedelta(days=5))
    db_session.add(case)
    await db_session.commit()

    flagged = await scan_case_sla_breaches(db_session, now=datetime.now(UTC))

    assert flagged == 0
    await db_session.refresh(case)
    assert case.sla_breached is False
    assert case.sla_due_at is None


@pytest.mark.asyncio
async def test_scan_stamps_due_at_without_breach(db_session):
    await save_sla_policy(db_session, {"enabled": True, "targets_minutes": {"high": 240}})
    await db_session.commit()
    created = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    case = _make_case(severity="high", created_at=created)
    db_session.add(case)
    await db_session.commit()

    # now is before the 4h due time -> due stamped, not breached.
    flagged = await scan_case_sla_breaches(db_session, now=created + timedelta(minutes=10))

    assert flagged == 0
    await db_session.refresh(case)
    assert case.sla_breached is False
    assert case.sla_due_at == created + timedelta(minutes=240)


@pytest.mark.asyncio
async def test_scan_flags_breached_open_case(db_session):
    await save_sla_policy(db_session, {"enabled": True, "targets_minutes": {"critical": 60}})
    await db_session.commit()
    created = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    case = _make_case(severity="critical", created_at=created)
    db_session.add(case)
    await db_session.commit()

    flagged = await scan_case_sla_breaches(db_session, now=created + timedelta(hours=3))

    assert flagged == 1
    await db_session.refresh(case)
    assert case.sla_breached is True
    assert case.sla_due_at == created + timedelta(minutes=60)


@pytest.mark.asyncio
async def test_scan_skips_closed_case(db_session):
    await save_sla_policy(db_session, {"enabled": True, "targets_minutes": {"critical": 60}})
    await db_session.commit()
    created = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    case = _make_case(
        severity="critical", created_at=created, status=CaseStatus.CLOSED.value
    )
    db_session.add(case)
    await db_session.commit()

    flagged = await scan_case_sla_breaches(db_session, now=created + timedelta(hours=3))

    assert flagged == 0
    await db_session.refresh(case)
    assert case.sla_breached is False


@pytest.mark.asyncio
async def test_scan_is_idempotent(db_session):
    await save_sla_policy(db_session, {"enabled": True, "targets_minutes": {"critical": 60}})
    await db_session.commit()
    created = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    case = _make_case(severity="critical", created_at=created)
    db_session.add(case)
    await db_session.commit()

    first = await scan_case_sla_breaches(db_session, now=created + timedelta(hours=3))
    second = await scan_case_sla_breaches(db_session, now=created + timedelta(hours=4))

    assert first == 1
    assert second == 0  # already flagged, not double-counted
    await db_session.refresh(case)
    assert case.sla_breached is True


@pytest.mark.asyncio
async def test_execute_case_sla_scan_flags_open_case(db_session, monkeypatch):
    """The scheduler job runs the scan against its own session and persists flags."""
    import app.services.scheduler as scheduler_mod

    await save_sla_policy(db_session, {"enabled": True, "targets_minutes": {"critical": 60}})
    await db_session.commit()
    created = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    case = _make_case(severity="critical", created_at=created)
    db_session.add(case)
    await db_session.commit()
    case_id = case.id

    service = scheduler_mod.SchedulerService()
    # Drive the scan with the shared test session instead of a real engine
    # session. The job's ``finally`` calls ``session.close()``; on the real
    # engine that just returns the connection to the pool, but on the shared
    # fixture session it would expunge every tracked object (detaching ``case``
    # so the assertions below could no longer refresh it). Hand the job a proxy
    # that delegates everything to ``db_session`` except ``close()``, which is a
    # no-op — exercising the production session handling without tearing down the
    # fixture session.
    monkeypatch.setattr(
        service, "_get_session", lambda: _yield_session(_NonClosingSession(db_session))
    )

    await service._execute_case_sla_scan()

    await db_session.refresh(case)
    assert case.sla_breached is True
    assert case.id == case_id


class _NonClosingSession:
    """Proxy around an AsyncSession that swallows ``close()``.

    Lets a scheduler job run against the shared test session without the job's
    ``finally: await session.close()`` detaching the fixture's tracked objects.
    """

    def __init__(self, session):
        self._session = session

    async def close(self):  # no-op: keep the shared fixture session alive
        return None

    def __getattr__(self, name):
        return getattr(self._session, name)


async def _yield_session(session):
    return session
