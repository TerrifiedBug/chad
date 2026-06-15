"""Tests for enterprise IdP depth (I4): session revocation + enforced MFA."""

import uuid

import pytest
from sqlalchemy import select

from app.core.security import create_access_token, get_password_hash
from app.models.setting import Setting
from app.models.user import AuthMethod, User, UserRole


def _auth(user: User, token_version: int = 0) -> dict[str, str]:
    token = create_access_token(data={"sub": str(user.id)}, token_version=token_version)
    return {"Authorization": f"Bearer {token}"}


async def _make_user(session, email, role=UserRole.ANALYST, totp=False) -> User:
    user = User(
        id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw-12345678"),
        role=role, is_active=True, auth_method=AuthMethod.LOCAL, totp_enabled=totp,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_revoke_user_sessions_bumps_token_version(client, test_session):
    admin = await _make_user(test_session, "admin@example.com", UserRole.ADMIN)
    target = await _make_user(test_session, "t@example.com")
    assert target.token_version == 0

    resp = await client.post(f"/api/users/{target.id}/revoke-sessions", headers=_auth(admin), json={})
    assert resp.status_code == 200, resp.text

    refreshed = (await test_session.execute(select(User).where(User.id == target.id))).scalar_one()
    assert refreshed.token_version == 1

    # The target's old token (version 0) is now rejected.
    me = await client.get("/api/auth/me", headers=_auth(target, token_version=0))
    assert me.status_code == 401


@pytest.mark.asyncio
async def test_revoke_all_sessions(client, test_session):
    admin = await _make_user(test_session, "admin2@example.com", UserRole.ADMIN)
    u1 = await _make_user(test_session, "u1@example.com")
    u2 = await _make_user(test_session, "u2@example.com")

    resp = await client.post("/api/auth/revoke-all-sessions", headers=_auth(admin), json={})
    assert resp.status_code == 200, resp.text

    for u in (u1, u2, admin):
        refreshed = (await test_session.execute(select(User).where(User.id == u.id))).scalar_one()
        assert refreshed.token_version == 1


@pytest.mark.asyncio
async def test_non_admin_cannot_revoke_all(client, test_session):
    analyst = await _make_user(test_session, "a@example.com")
    resp = await client.post("/api/auth/revoke-all-sessions", headers=_auth(analyst), json={})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_enforce_mfa_surfaces_required_flag(client, test_session):
    user = await _make_user(test_session, "nomfa@example.com", totp=False)
    # No enforcement yet → not required.
    me = await client.get("/api/auth/me", headers=_auth(user))
    assert me.json()["mfa_required"] is False

    test_session.add(Setting(key="security", value={"enforce_mfa": True}))
    await test_session.commit()

    me2 = await client.get("/api/auth/me", headers=_auth(user))
    body = me2.json()
    assert body["mfa_enforced"] is True
    assert body["mfa_required"] is True


@pytest.mark.asyncio
async def test_enforce_mfa_satisfied_when_totp_enabled(client, test_session):
    user = await _make_user(test_session, "hasmfa@example.com", totp=True)
    test_session.add(Setting(key="security", value={"enforce_mfa": True}))
    await test_session.commit()
    me = await client.get("/api/auth/me", headers=_auth(user))
    assert me.json()["mfa_required"] is False
