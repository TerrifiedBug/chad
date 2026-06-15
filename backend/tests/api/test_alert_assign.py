"""Tests for teammate alert assignment authorization."""

import uuid

import pytest

from app.api.deps import get_opensearch_client
from app.core.security import create_access_token, get_password_hash
from app.main import app
from app.models.team import Team
from app.models.user import User, UserRole


class FakeOpenSearch:
    """Minimal stand-in: one alert hit, captures the assignment update."""

    def __init__(self):
        self.last_update = None

    def search(self, index, body):
        return {
            "hits": {"hits": [{"_index": "chad-alerts-2026-06", "_id": "doc-1"}]}
        }

    def update(self, index, id, body, refresh=False):
        self.last_update = body
        return {"result": "updated"}


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


@pytest.fixture
def fake_os():
    fake = FakeOpenSearch()
    app.dependency_overrides[get_opensearch_client] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_opensearch_client, None)


@pytest.mark.asyncio
async def test_self_assign_without_body(client, test_session, fake_os):
    actor = await _make_user(test_session, "actor@example.com")
    # Empty JSON body mirrors the frontend's api.post (always sends json
    # Content-Type); the request-validation middleware requires it on POST.
    resp = await client.post("/api/alerts/abc/assign", headers=_auth(actor), json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["owner"] == "actor@example.com"
    assert fake_os.last_update["doc"]["owner_id"] == str(actor.id)


@pytest.mark.asyncio
async def test_assign_to_teammate(client, test_session, fake_os):
    team = Team(id=uuid.uuid4(), name="SOC")
    test_session.add(team)
    await test_session.commit()
    actor = await _make_user(test_session, "lead@example.com", team_id=team.id)
    mate = await _make_user(test_session, "mate@example.com", team_id=team.id)

    resp = await client.post(
        "/api/alerts/abc/assign",
        headers=_auth(actor),
        json={"assignee_id": str(mate.id)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["owner"] == "mate@example.com"
    assert fake_os.last_update["doc"]["owner_id"] == str(mate.id)


@pytest.mark.asyncio
async def test_cannot_assign_across_teams(client, test_session, fake_os):
    team_a = Team(id=uuid.uuid4(), name="Team A")
    team_b = Team(id=uuid.uuid4(), name="Team B")
    test_session.add_all([team_a, team_b])
    await test_session.commit()
    actor = await _make_user(test_session, "a@example.com", team_id=team_a.id)
    outsider = await _make_user(test_session, "b@example.com", team_id=team_b.id)

    resp = await client.post(
        "/api/alerts/abc/assign",
        headers=_auth(actor),
        json={"assignee_id": str(outsider.id)},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_assign_across_teams(client, test_session, fake_os):
    team_b = Team(id=uuid.uuid4(), name="Team B2")
    test_session.add(team_b)
    await test_session.commit()
    admin = await _make_user(test_session, "admin@example.com", role=UserRole.ADMIN)
    target = await _make_user(test_session, "t@example.com", team_id=team_b.id)

    resp = await client.post(
        "/api/alerts/abc/assign",
        headers=_auth(admin),
        json={"assignee_id": str(target.id)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["owner"] == "t@example.com"


@pytest.mark.asyncio
async def test_assign_to_unknown_user_404(client, test_session, fake_os):
    actor = await _make_user(test_session, "actor2@example.com")
    resp = await client.post(
        "/api/alerts/abc/assign",
        headers=_auth(actor),
        json={"assignee_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404
