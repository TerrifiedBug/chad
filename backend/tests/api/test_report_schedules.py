"""Tests for scheduled reporting (F5): report builder + schedule API."""

import uuid

import pytest

from app.core.security import create_access_token, get_password_hash
from app.models.user import User, UserRole
from app.services.reporting import COMPLIANCE_FRAMEWORKS, build_report, compute_next_run


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role) -> User:
    user = User(id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw-12345678"),
                role=role, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


def test_compute_next_run_cadences():
    import datetime as dt
    now = dt.datetime(2026, 6, 15, tzinfo=dt.UTC)
    assert (compute_next_run(now, "daily") - now).days == 1
    assert (compute_next_run(now, "weekly") - now).days == 7
    assert (compute_next_run(now, "monthly") - now).days == 30


@pytest.mark.asyncio
async def test_build_coverage_report(test_session):
    report = await build_report(test_session, None, "coverage")
    assert report["type"] == "coverage"
    section = report["sections"][0]
    assert "coverage_pct" in section


@pytest.mark.asyncio
async def test_build_rule_health_report(test_session):
    report = await build_report(test_session, None, "rule_health")
    assert report["sections"][0]["title"] == "Rule hygiene"


@pytest.mark.asyncio
async def test_build_compliance_report_maps_controls(test_session):
    report = await build_report(test_session, None, "compliance", framework="soc2")
    assert report["framework"] == "soc2"
    control_section = report["sections"][-1]
    assert len(control_section["controls"]) == len(COMPLIANCE_FRAMEWORKS["soc2"]["controls"])
    assert all("addressed" in c for c in control_section["controls"])


@pytest.mark.asyncio
async def test_build_compliance_unknown_framework_raises(test_session):
    with pytest.raises(ValueError):
        await build_report(test_session, None, "compliance", framework="nope")


@pytest.mark.asyncio
async def test_kpis_degrade_without_opensearch(test_session):
    report = await build_report(test_session, None, "detection_kpis")
    assert report["sections"][0]["available"] is False


@pytest.mark.asyncio
async def test_schedule_crud_and_preview(client, test_session):
    admin = await _make_user(test_session, "admin@example.com", UserRole.ADMIN)

    # Preview is available to any authed user.
    prev = await client.get("/api/report-schedules/preview?report_type=coverage", headers=_auth(admin))
    assert prev.status_code == 200, prev.text
    assert prev.json()["type"] == "coverage"

    created = await client.post(
        "/api/report-schedules", headers=_auth(admin),
        json={"name": "Weekly coverage", "report_type": "coverage", "cadence": "weekly",
              "delivery_type": "webhook", "delivery_target": "https://siem.example.com/reports"},
    )
    assert created.status_code == 201, created.text
    assert created.json()["next_run_at"] is not None
    sid = created.json()["id"]

    listed = await client.get("/api/report-schedules", headers=_auth(admin))
    assert any(s["id"] == sid for s in listed.json())

    deleted = await client.delete(f"/api/report-schedules/{sid}", headers=_auth(admin))
    assert deleted.status_code == 204


@pytest.mark.asyncio
async def test_compliance_schedule_requires_framework(client, test_session):
    admin = await _make_user(test_session, "admin2@example.com", UserRole.ADMIN)
    resp = await client.post(
        "/api/report-schedules", headers=_auth(admin),
        json={"name": "C", "report_type": "compliance", "cadence": "monthly"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_delivery_url_rejected(client, test_session):
    admin = await _make_user(test_session, "admin3@example.com", UserRole.ADMIN)
    resp = await client.post(
        "/api/report-schedules", headers=_auth(admin),
        json={"name": "Bad", "report_type": "coverage", "cadence": "weekly",
              "delivery_target": "ftp://x/y"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_non_admin_cannot_create(client, test_session):
    analyst = await _make_user(test_session, "a@example.com", UserRole.ANALYST)
    resp = await client.post(
        "/api/report-schedules", headers=_auth(analyst),
        json={"name": "X", "report_type": "coverage", "cadence": "weekly"},
    )
    assert resp.status_code == 403
