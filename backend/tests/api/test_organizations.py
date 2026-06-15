"""Tests for the organization (tenant) management API."""

import uuid

import pytest

from app.core.org_constants import DEFAULT_ORG_ID, DEFAULT_ORG_SLUG
from app.core.security import create_access_token, get_password_hash
from app.models.organization import Organization
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role) -> User:
    user = User(id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw-12345678"),
                role=role, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _seed_default(session):
    session.add(Organization(id=DEFAULT_ORG_ID, name="Default", slug=DEFAULT_ORG_SLUG))
    await session.commit()


@pytest.mark.asyncio
async def test_non_admin_forbidden(client, test_session):
    await _seed_default(test_session)
    analyst = await _make_user(test_session, "a@example.com", UserRole.ANALYST)
    assert (await client.get("/api/organizations", headers=_auth(analyst))).status_code == 403


@pytest.mark.asyncio
async def test_create_and_list(client, test_session):
    await _seed_default(test_session)
    admin = await _make_user(test_session, "admin@example.com", UserRole.ADMIN)
    resp = await client.post(
        "/api/organizations", headers=_auth(admin),
        json={"name": "Acme Corp", "slug": "acme", "plan": "enterprise"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["slug"] == "acme"

    listed = await client.get("/api/organizations", headers=_auth(admin))
    slugs = {o["slug"] for o in listed.json()}
    assert {"default", "acme"} <= slugs


@pytest.mark.asyncio
async def test_duplicate_slug_conflict(client, test_session):
    await _seed_default(test_session)
    admin = await _make_user(test_session, "admin2@example.com", UserRole.ADMIN)
    payload = {"name": "Dup", "slug": "dupe"}
    assert (await client.post("/api/organizations", headers=_auth(admin), json=payload)).status_code == 201
    assert (await client.post("/api/organizations", headers=_auth(admin), json=payload)).status_code == 409


@pytest.mark.asyncio
async def test_invalid_slug_rejected(client, test_session):
    await _seed_default(test_session)
    admin = await _make_user(test_session, "admin3@example.com", UserRole.ADMIN)
    resp = await client.post(
        "/api/organizations", headers=_auth(admin), json={"name": "Bad", "slug": "AB_bad!"}
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_suspend_and_restore(client, test_session):
    await _seed_default(test_session)
    admin = await _make_user(test_session, "admin4@example.com", UserRole.ADMIN)
    org_id = (await client.post("/api/organizations", headers=_auth(admin),
                                json={"name": "S", "slug": "suspendme"})).json()["id"]

    susp = await client.put(f"/api/organizations/{org_id}", headers=_auth(admin), json={"suspended": True})
    assert susp.json()["suspended_at"] is not None
    restore = await client.put(f"/api/organizations/{org_id}", headers=_auth(admin), json={"suspended": False})
    assert restore.json()["suspended_at"] is None


@pytest.mark.asyncio
async def test_default_org_protected(client, test_session):
    await _seed_default(test_session)
    admin = await _make_user(test_session, "admin5@example.com", UserRole.ADMIN)
    # Cannot suspend or delete the default org.
    assert (await client.put(f"/api/organizations/{DEFAULT_ORG_ID}", headers=_auth(admin),
                             json={"suspended": True})).status_code == 400
    assert (await client.delete(f"/api/organizations/{DEFAULT_ORG_ID}", headers=_auth(admin))).status_code == 400
