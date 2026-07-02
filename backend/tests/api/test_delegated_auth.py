"""Delegated (VectorFlow session) auth funnel tests.

Covers the auth-funnel rework of app/api/deps.py: HTTPBearer(auto_error=False),
cookie-first delegated mode, JIT provisioning, per-request role re-sync, and
gating of CHAD-local auth surfaces when CHAD_DELEGATED_AUTH is on.
"""

import pytest
from httpx import AsyncClient


class TestBearerDependency:
    @pytest.mark.asyncio
    async def test_bearer_flow_still_works(self, authenticated_client: AsyncClient):
        """Existing token pattern (conftest authenticated_client) must be unchanged."""
        resp = await authenticated_client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["email"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_missing_credentials_is_401_not_403(self, client: AsyncClient):
        """HTTPBearer(auto_error=True) used to 403 before any cookie branch could run."""
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Not authenticated"


import uuid
from unittest.mock import patch

from sqlalchemy import select

from app.core.vf_session import VfSessionClaims, VfSessionExpired
from app.models.audit_log import AuditLog
from app.models.user import TeamSource, User, UserRole

FAR_FUTURE = 4_102_444_800  # 2100-01-01


def _vf_claims(**overrides) -> VfSessionClaims:
    base = dict(
        user_id="vf-user-1",
        email="Suite.User@Example.com",
        name="Suite User",
        suite_role="editor",
        org_id="default",
        provider="google",
        authed_at=1_751_000_000,
        exp=FAR_FUTURE,
    )
    base.update(overrides)
    return VfSessionClaims(**base)


def _delegated(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "CHAD_DELEGATED_AUTH", True)
    monkeypatch.setattr(settings, "VF_SESSION_SECRET", "a" * 32)


class TestDelegatedCookieAuth:
    @pytest.mark.asyncio
    async def test_vf_session_jit_provisions_user(self, client, test_session, monkeypatch):
        _delegated(monkeypatch)
        with patch("app.api.deps.decode_vf_session", return_value=_vf_claims()):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "suite.user@example.com"  # lowercased email key
        assert body["role"] == "analyst"  # suite editor -> chad analyst

        result = await test_session.execute(
            select(User).where(User.email == "suite.user@example.com")
        )
        user = result.scalar_one()
        assert user.provisioned_via == "vectorflow"
        assert user.password_hash is None

        audit = await test_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.suite_link")
        )
        assert audit.scalars().first() is not None

    @pytest.mark.asyncio
    async def test_role_resynced_per_request(self, client, test_session, monkeypatch):
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.VIEWER, provisioned_via="vectorflow", is_active=True,
        )
        test_session.add(user)
        await test_session.commit()
        with patch(
            "app.api.deps.decode_vf_session",
            return_value=_vf_claims(suite_role="admin"),
        ):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    @pytest.mark.asyncio
    async def test_manual_team_source_role_not_clobbered(
        self, client, test_session, monkeypatch
    ):
        """team_source='manual' is sacred — same rule as sso_reconcile.py:115-127."""
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.ADMIN, provisioned_via="vectorflow", is_active=True,
            team_source=TeamSource.MANUAL.value,
        )
        test_session.add(user)
        await test_session.commit()
        with patch(
            "app.api.deps.decode_vf_session",
            return_value=_vf_claims(suite_role="viewer"),
        ):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    @pytest.mark.asyncio
    async def test_inactive_user_is_403(self, client, test_session, monkeypatch):
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.VIEWER, provisioned_via="vectorflow", is_active=False,
        )
        test_session.add(user)
        await test_session.commit()
        with patch("app.api.deps.decode_vf_session", return_value=_vf_claims()):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_token_version_not_checked_for_vf_sessions(
        self, client, test_session, monkeypatch
    ):
        """VF owns session revocation (single logout kills the shared cookie)."""
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.VIEWER, provisioned_via="vectorflow", is_active=True,
            token_version=7,  # would invalidate any CHAD bearer token
        )
        test_session.add(user)
        await test_session.commit()
        with patch("app.api.deps.decode_vf_session", return_value=_vf_claims()):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_expired_vf_session_is_401(self, client, monkeypatch):
        _delegated(monkeypatch)
        with patch(
            "app.api.deps.decode_vf_session", side_effect=VfSessionExpired("exp")
        ):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_flag_off_ignores_cookies(self, client):
        """Standalone mode (default): VF cookies are never even decoded."""
        client.cookies.set("authjs.session-token", "junk")
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401
