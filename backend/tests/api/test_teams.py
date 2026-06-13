"""Tests for team management API and resource-scoped RBAC."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_db
from app.main import app
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleStatus
from app.models.team import Team


async def _viewer_client(test_session, normal_token):
    async def override():
        yield test_session

    app.dependency_overrides[get_db] = override
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {normal_token}"},
    )


class TestTeamsCrud:
    @pytest.mark.asyncio
    async def test_admin_can_create_and_list_team(self, authenticated_client: AsyncClient):
        resp = await authenticated_client.post("/api/teams", json={"name": "Blue Team"})
        assert resp.status_code == 201
        assert resp.json()["name"] == "Blue Team"

        listed = await authenticated_client.get("/api/teams")
        assert listed.status_code == 200
        assert any(t["name"] == "Blue Team" for t in listed.json())

    @pytest.mark.asyncio
    async def test_duplicate_team_name_rejected(self, authenticated_client: AsyncClient):
        await authenticated_client.post("/api/teams", json={"name": "Dup"})
        resp = await authenticated_client.post("/api/teams", json={"name": "Dup"})
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_non_admin_cannot_manage_teams(self, client: AsyncClient, normal_token: str):
        resp = await client.post(
            "/api/teams",
            json={"name": "Nope"},
            headers={"Authorization": f"Bearer {normal_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_add_and_remove_member(
        self, authenticated_client: AsyncClient, normal_user, test_session
    ):
        team = (await authenticated_client.post("/api/teams", json={"name": "Ops"})).json()
        add = await authenticated_client.post(
            f"/api/teams/{team['id']}/members", json={"user_id": str(normal_user.id)}
        )
        assert add.status_code == 204
        await test_session.refresh(normal_user)
        assert str(normal_user.team_id) == team["id"]

        rm = await authenticated_client.delete(
            f"/api/teams/{team['id']}/members/{normal_user.id}"
        )
        assert rm.status_code == 204
        await test_session.refresh(normal_user)
        assert normal_user.team_id is None


class TestResourceScoping:
    @pytest.mark.asyncio
    async def test_rules_scoped_to_team_plus_global(
        self, test_session, admin_user, normal_user, normal_token, authenticated_client
    ):
        team_a = Team(id=uuid.uuid4(), name="A")
        team_b = Team(id=uuid.uuid4(), name="B")
        test_session.add_all([team_a, team_b])
        await test_session.flush()

        normal_user.team_id = team_a.id

        ip = IndexPattern(name="ip", pattern="ip-*", percolator_index="chad-percolator-ip")
        test_session.add(ip)
        await test_session.flush()

        def _rule(title, team_id):
            return Rule(
                id=uuid.uuid4(), title=title, yaml_content="title: x",
                severity="medium", status=RuleStatus.UNDEPLOYED,
                index_pattern_id=ip.id, created_by=admin_user.id, team_id=team_id,
            )

        test_session.add_all([
            _rule("a-rule", team_a.id),
            _rule("b-rule", team_b.id),
            _rule("global-rule", None),
        ])
        await test_session.commit()

        # Admin sees everything (authenticated_client already overrides get_db).
        admin_resp = await authenticated_client.get("/api/rules")
        admin_titles = {r["title"] for r in admin_resp.json()}
        assert {"a-rule", "b-rule", "global-rule"} <= admin_titles

        # Viewer in team A sees team-A + global, never team-B. Reuses the same
        # test_session override; the authenticated_client fixture clears it.
        viewer = await _viewer_client(test_session, normal_token)
        try:
            resp = await viewer.get("/api/rules")
        finally:
            await viewer.aclose()

        assert resp.status_code == 200
        titles = {r["title"] for r in resp.json()}
        assert "a-rule" in titles
        assert "global-rule" in titles
        assert "b-rule" not in titles
