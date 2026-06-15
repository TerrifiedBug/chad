"""Tests for the case management API."""

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
async def test_create_case_assigns_sequential_numbers(client, test_session):
    user = await _make_user(test_session, "a@example.com")
    first = await client.post("/api/cases", headers=_auth(user), json={"title": "Phishing wave"})
    second = await client.post("/api/cases", headers=_auth(user), json={"title": "Lateral move"})
    assert first.status_code == 201, first.text
    assert second.status_code == 201
    assert second.json()["number"] == first.json()["number"] + 1


@pytest.mark.asyncio
async def test_create_case_with_seed_alerts_and_timeline(client, test_session):
    user = await _make_user(test_session, "b@example.com")
    resp = await client.post(
        "/api/cases",
        headers=_auth(user),
        json={"title": "Beacon", "alert_ids": ["alert-1", "alert-2"]},
    )
    assert resp.status_code == 201
    case_id = resp.json()["id"]
    assert resp.json()["alert_count"] == 2

    detail = await client.get(f"/api/cases/{case_id}", headers=_auth(user))
    body = detail.json()
    assert len(body["alerts"]) == 2
    types = {e["event_type"] for e in body["events"]}
    assert "created" in types and "alert_linked" in types


@pytest.mark.asyncio
async def test_status_change_records_event_and_closed_at(client, test_session):
    user = await _make_user(test_session, "c@example.com")
    case_id = (await client.post("/api/cases", headers=_auth(user), json={"title": "X"})).json()["id"]

    closed = await client.post(
        f"/api/cases/{case_id}/status", headers=_auth(user),
        json={"status": "closed", "note": "benign"},
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"] is not None

    reopened = await client.post(
        f"/api/cases/{case_id}/status", headers=_auth(user), json={"status": "investigating"}
    )
    assert reopened.json()["closed_at"] is None
    detail = await client.get(f"/api/cases/{case_id}", headers=_auth(user))
    types = [e["event_type"] for e in detail.json()["events"]]
    assert "closed" in types and "reopened" in types


@pytest.mark.asyncio
async def test_invalid_status_rejected(client, test_session):
    user = await _make_user(test_session, "d@example.com")
    case_id = (await client.post("/api/cases", headers=_auth(user), json={"title": "X"})).json()["id"]
    resp = await client.post(
        f"/api/cases/{case_id}/status", headers=_auth(user), json={"status": "bogus"}
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_add_and_remove_alerts_are_idempotent(client, test_session):
    user = await _make_user(test_session, "e@example.com")
    case_id = (await client.post("/api/cases", headers=_auth(user), json={"title": "X"})).json()["id"]

    r1 = await client.post(f"/api/cases/{case_id}/alerts", headers=_auth(user),
                           json={"alert_ids": ["a1", "a2"]})
    assert r1.json()["alert_count"] == 2
    # Re-adding a1 is a no-op (idempotent).
    r2 = await client.post(f"/api/cases/{case_id}/alerts", headers=_auth(user),
                           json={"alert_ids": ["a1", "a3"]})
    assert r2.json()["alert_count"] == 3

    rem = await client.delete(f"/api/cases/{case_id}/alerts/a1", headers=_auth(user))
    assert rem.status_code == 204
    detail = await client.get(f"/api/cases/{case_id}", headers=_auth(user))
    assert detail.json()["alert_count"] == 2


@pytest.mark.asyncio
async def test_assign_requires_same_team(client, test_session):
    team_a = Team(id=uuid.uuid4(), name="A")
    team_b = Team(id=uuid.uuid4(), name="B")
    test_session.add_all([team_a, team_b])
    await test_session.commit()
    actor = await _make_user(test_session, "actor@example.com", team_id=team_a.id)
    outsider = await _make_user(test_session, "out@example.com", team_id=team_b.id)
    case_id = (await client.post("/api/cases", headers=_auth(actor), json={"title": "X"})).json()["id"]

    bad = await client.post(f"/api/cases/{case_id}/assign", headers=_auth(actor),
                            json={"owner_id": str(outsider.id)})
    assert bad.status_code == 403


@pytest.mark.asyncio
async def test_team_scoping_hides_other_team_cases(client, test_session):
    team_a = Team(id=uuid.uuid4(), name="TA")
    team_b = Team(id=uuid.uuid4(), name="TB")
    test_session.add_all([team_a, team_b])
    await test_session.commit()
    a_user = await _make_user(test_session, "ua@example.com", team_id=team_a.id)
    b_user = await _make_user(test_session, "ub@example.com", team_id=team_b.id)

    a_case = (await client.post("/api/cases", headers=_auth(a_user), json={"title": "A case"})).json()
    # Team B user cannot see or fetch team A's case.
    listing = await client.get("/api/cases", headers=_auth(b_user))
    assert all(c["id"] != a_case["id"] for c in listing.json()["cases"])
    fetch = await client.get(f"/api/cases/{a_case['id']}", headers=_auth(b_user))
    assert fetch.status_code == 404


@pytest.mark.asyncio
async def test_comment_add_and_author_only_delete(client, test_session):
    team = Team(id=uuid.uuid4(), name="C")
    test_session.add(team)
    await test_session.commit()
    author = await _make_user(test_session, "author@example.com", team_id=team.id)
    other = await _make_user(test_session, "other@example.com", team_id=team.id)
    case_id = (await client.post("/api/cases", headers=_auth(author), json={"title": "X"})).json()["id"]

    c = await client.post(f"/api/cases/{case_id}/comments", headers=_auth(author),
                          json={"content": "looks malicious"})
    assert c.status_code == 201
    comment_id = c.json()["id"]

    # Another teammate cannot delete the author's comment.
    deny = await client.delete(f"/api/cases/{case_id}/comments/{comment_id}", headers=_auth(other))
    assert deny.status_code == 403
    ok = await client.delete(f"/api/cases/{case_id}/comments/{comment_id}", headers=_auth(author))
    assert ok.status_code == 204


@pytest.mark.asyncio
async def test_viewer_cannot_create_case(client, test_session):
    viewer = await _make_user(test_session, "v@example.com", role=UserRole.VIEWER)
    resp = await client.post("/api/cases", headers=_auth(viewer), json={"title": "X"})
    assert resp.status_code == 403
