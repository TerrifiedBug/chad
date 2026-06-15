"""Tests for the SLA policy API and assignable-users listing."""

import uuid

import pytest

from app.core.security import create_access_token, get_password_hash
from app.models.team import Team
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role=UserRole.ANALYST, team_id=None) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=get_password_hash("pw-12345678"),
        role=role,
        is_active=True,
        team_id=team_id,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_get_sla_policy_returns_defaults(client, test_session):
    user = await _make_user(test_session, "viewer@example.com", role=UserRole.VIEWER)
    resp = await client.get("/api/sla-policy", headers=_auth(user))
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["targets_minutes"]["critical"] == 60


@pytest.mark.asyncio
async def test_only_admin_can_update_policy(client, test_session):
    analyst = await _make_user(test_session, "analyst@example.com")
    resp = await client.put(
        "/api/sla-policy",
        headers=_auth(analyst),
        json={"enabled": True, "targets_minutes": {"critical": 30, "high": 120,
              "medium": 480, "low": 1440, "informational": 0}},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_updates_policy(client, test_session):
    admin = await _make_user(test_session, "admin@example.com", role=UserRole.ADMIN)
    resp = await client.put(
        "/api/sla-policy",
        headers=_auth(admin),
        json={"enabled": True, "targets_minutes": {"critical": 30, "high": 120,
              "medium": 480, "low": 1440, "informational": 0}},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is True
    assert resp.json()["targets_minutes"]["critical"] == 30

    # Persisted across reads.
    again = await client.get("/api/sla-policy", headers=_auth(admin))
    assert again.json()["targets_minutes"]["critical"] == 30


@pytest.mark.asyncio
async def test_assignable_users_scoped_to_team(client, test_session):
    team = Team(id=uuid.uuid4(), name="SOC")
    other = Team(id=uuid.uuid4(), name="Other")
    test_session.add_all([team, other])
    await test_session.commit()
    actor = await _make_user(test_session, "actor@example.com", team_id=team.id)
    await _make_user(test_session, "mate@example.com", team_id=team.id)
    await _make_user(test_session, "stranger@example.com", team_id=other.id)

    resp = await client.get("/api/alerts/assignable-users", headers=_auth(actor))
    assert resp.status_code == 200
    emails = {u["email"] for u in resp.json()}
    assert emails == {"actor@example.com", "mate@example.com"}


@pytest.mark.asyncio
async def test_assignable_users_admin_sees_all(client, test_session):
    admin = await _make_user(test_session, "admin2@example.com", role=UserRole.ADMIN)
    await _make_user(test_session, "u1@example.com")
    await _make_user(test_session, "u2@example.com")

    resp = await client.get("/api/alerts/assignable-users", headers=_auth(admin))
    assert resp.status_code == 200
    emails = {u["email"] for u in resp.json()}
    assert {"admin2@example.com", "u1@example.com", "u2@example.com"} <= emails
