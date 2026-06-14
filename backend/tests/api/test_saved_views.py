"""Tests for the saved views (filter presets) API."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.models.team import Team
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session: AsyncSession, email: str, team_id=None) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=get_password_hash("pw-12345678"),
        role=UserRole.ANALYST,
        is_active=True,
        team_id=team_id,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_create_and_list_own_view(client, test_session):
    user = await _make_user(test_session, "owner@example.com")
    resp = await client.post(
        "/api/saved-views",
        headers=_auth(user),
        json={
            "name": "Critical new",
            "resource": "alerts",
            "filters": {"status": "new", "severity": ["critical"]},
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "Critical new"
    assert body["filters"]["severity"] == ["critical"]
    assert body["is_shared"] is False

    listed = await client.get("/api/saved-views?resource=alerts", headers=_auth(user))
    assert listed.status_code == 200
    assert len(listed.json()) == 1


@pytest.mark.asyncio
async def test_invalid_resource_rejected(client, test_session):
    user = await _make_user(test_session, "owner2@example.com")
    resp = await client.post(
        "/api/saved-views",
        headers=_auth(user),
        json={"name": "Bad", "resource": "nonsense", "filters": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_private_view_not_visible_to_others(client, test_session):
    team = Team(id=uuid.uuid4(), name="Blue Team")
    test_session.add(team)
    await test_session.commit()
    owner = await _make_user(test_session, "a@example.com", team_id=team.id)
    other = await _make_user(test_session, "b@example.com", team_id=team.id)

    # Private (not shared) view
    await client.post(
        "/api/saved-views",
        headers=_auth(owner),
        json={"name": "Mine", "resource": "alerts", "filters": {}, "is_shared": False},
    )
    # Teammate should not see a private view
    other_list = await client.get("/api/saved-views", headers=_auth(other))
    assert other_list.status_code == 200
    assert other_list.json() == []


@pytest.mark.asyncio
async def test_shared_view_visible_to_teammate_only(client, test_session):
    team = Team(id=uuid.uuid4(), name="Red Team")
    test_session.add(team)
    await test_session.commit()
    owner = await _make_user(test_session, "owner3@example.com", team_id=team.id)
    teammate = await _make_user(test_session, "mate@example.com", team_id=team.id)
    outsider = await _make_user(test_session, "out@example.com")  # no team

    await client.post(
        "/api/saved-views",
        headers=_auth(owner),
        json={"name": "Team triage", "resource": "alerts", "filters": {}, "is_shared": True},
    )
    mate_list = await client.get("/api/saved-views", headers=_auth(teammate))
    assert len(mate_list.json()) == 1
    out_list = await client.get("/api/saved-views", headers=_auth(outsider))
    assert out_list.json() == []


@pytest.mark.asyncio
async def test_only_owner_can_update_or_delete(client, test_session):
    team = Team(id=uuid.uuid4(), name="Green Team")
    test_session.add(team)
    await test_session.commit()
    owner = await _make_user(test_session, "owner4@example.com", team_id=team.id)
    teammate = await _make_user(test_session, "mate2@example.com", team_id=team.id)

    created = await client.post(
        "/api/saved-views",
        headers=_auth(owner),
        json={"name": "Shared", "resource": "alerts", "filters": {}, "is_shared": True},
    )
    view_id = created.json()["id"]

    # Teammate can see it but cannot modify it.
    forbidden = await client.put(
        f"/api/saved-views/{view_id}", headers=_auth(teammate), json={"name": "Hijack"}
    )
    assert forbidden.status_code == 403
    deny_delete = await client.delete(f"/api/saved-views/{view_id}", headers=_auth(teammate))
    assert deny_delete.status_code == 403

    # Owner can.
    ok = await client.put(
        f"/api/saved-views/{view_id}", headers=_auth(owner), json={"name": "Renamed"}
    )
    assert ok.status_code == 200
    assert ok.json()["name"] == "Renamed"


@pytest.mark.asyncio
async def test_single_default_per_resource(client, test_session):
    user = await _make_user(test_session, "owner5@example.com")
    first = await client.post(
        "/api/saved-views",
        headers=_auth(user),
        json={"name": "One", "resource": "alerts", "filters": {}, "is_default": True},
    )
    second = await client.post(
        "/api/saved-views",
        headers=_auth(user),
        json={"name": "Two", "resource": "alerts", "filters": {}, "is_default": True},
    )
    assert first.status_code == 201 and second.status_code == 201

    views = (await client.get("/api/saved-views?resource=alerts", headers=_auth(user))).json()
    defaults = [v for v in views if v["is_default"]]
    assert len(defaults) == 1
    assert defaults[0]["name"] == "Two"


@pytest.mark.asyncio
async def test_duplicate_name_conflict(client, test_session):
    user = await _make_user(test_session, "owner6@example.com")
    payload = {"name": "Dupe", "resource": "alerts", "filters": {}}
    first = await client.post("/api/saved-views", headers=_auth(user), json=payload)
    assert first.status_code == 201
    dupe = await client.post("/api/saved-views", headers=_auth(user), json=payload)
    assert dupe.status_code == 409
