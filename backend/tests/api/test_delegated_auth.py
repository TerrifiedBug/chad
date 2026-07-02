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
    async def test_last_admin_role_not_downgraded(self, client, test_session, monkeypatch):
        """Last-admin guard: role re-sync must never demote the sole active
        admin, mirroring app/services/scim.py's count_active_admins guard
        (used by can_scim_deactivate's last-admin check)."""
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.ADMIN, provisioned_via="vectorflow", is_active=True,
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

        await test_session.refresh(user)
        assert user.role == UserRole.ADMIN

        audit = await test_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.suite_role_sync_blocked")
        )
        row = audit.scalars().first()
        assert row is not None
        assert row.details["current_role"] == "admin"
        assert row.details["attempted_role"] == "viewer"

    @pytest.mark.asyncio
    async def test_downgrade_proceeds_with_other_active_admins(
        self, client, test_session, monkeypatch
    ):
        """With another active admin present, the re-sync downgrade proceeds
        normally — the guard only blocks the *last* active admin."""
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.ADMIN, provisioned_via="vectorflow", is_active=True,
        )
        other_admin = User(
            id=uuid.uuid4(), email="other-admin@example.com", password_hash=None,
            role=UserRole.ADMIN, is_active=True,
        )
        test_session.add_all([user, other_admin])
        await test_session.commit()
        with patch(
            "app.api.deps.decode_vf_session",
            return_value=_vf_claims(suite_role="viewer"),
        ):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"

    @pytest.mark.asyncio
    async def test_role_change_writes_suite_role_sync_audit(
        self, client, test_session, monkeypatch
    ):
        """A real (non-blocked) role change from the suite must be audited —
        silent privilege changes are unacceptable even for legitimate syncs."""
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

        audit = await test_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.suite_role_sync")
        )
        row = audit.scalars().first()
        assert row is not None
        assert row.details["old_role"] == "viewer"
        assert row.details["new_role"] == "admin"

    @pytest.mark.asyncio
    async def test_noop_role_sync_writes_no_audit(self, client, test_session, monkeypatch):
        """suite_role maps to the same CHAD role the user already has —
        nothing changed, so nothing should be audited."""
        _delegated(monkeypatch)
        user = User(
            id=uuid.uuid4(), email="suite.user@example.com", password_hash=None,
            role=UserRole.ANALYST, provisioned_via="vectorflow", is_active=True,
        )
        test_session.add(user)
        await test_session.commit()
        with patch(
            "app.api.deps.decode_vf_session",
            return_value=_vf_claims(suite_role="editor"),  # editor -> analyst: no-op
        ):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"

        audit = await test_session.execute(
            select(AuditLog).where(
                AuditLog.action.in_(
                    ["auth.suite_role_sync", "auth.suite_role_sync_blocked"]
                )
            )
        )
        assert audit.scalars().first() is None

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


class TestRealCookieWiring:
    """Exercises the real request.cookies -> decode_vf_session wiring end to
    end — no patching of decode_vf_session itself. Uses the same cross-repo
    contract fixture as tests/core/test_vf_session.py::TestContractFixture
    (minted by VectorFlow's scripts/mint-test-session.mjs)."""

    @pytest.mark.asyncio
    async def test_real_vf_cookie_authenticates_auth_me(self, client, monkeypatch):
        import json
        from pathlib import Path

        from app.core.config import settings

        fixture_path = (
            Path(__file__).resolve().parents[1] / "fixtures" / "vf-session-fixture.json"
        )
        fixture = json.loads(fixture_path.read_text())

        monkeypatch.setattr(settings, "CHAD_DELEGATED_AUTH", True)
        monkeypatch.setattr(settings, "VF_SESSION_SECRET", fixture["secret"])

        client.cookies.set(fixture["cookie_name"], fixture["cookie_value"])
        resp = await client.get("/api/auth/me")

        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == fixture["expected_claims"]["email"].lower()
        assert body["role"] == "admin"


class _StubWebSocket:
    """Just enough of starlette.WebSocket for get_current_user_websocket
    (it only touches .headers, .query_params and — new — .cookies)."""

    def __init__(self, cookies=None, headers=None, query_params=None):
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.query_params = query_params or {}


class TestWebSocketDependency:
    @pytest.mark.asyncio
    async def test_vf_cookie_authenticates_websocket(self, test_session, monkeypatch):
        _delegated(monkeypatch)
        from app.api.deps import get_current_user_websocket

        ws = _StubWebSocket(cookies={"authjs.session-token": "opaque-jwe"})
        with patch("app.api.deps.decode_vf_session", return_value=_vf_claims()):
            user = await get_current_user_websocket(ws, test_session)
        assert user is not None
        assert user.email == "suite.user@example.com"
        assert user.provisioned_via == "vectorflow"

    @pytest.mark.asyncio
    async def test_bearer_protocol_fallback_still_works(
        self, test_session, test_user, monkeypatch
    ):
        _delegated(monkeypatch)
        from app.api.deps import get_current_user_websocket
        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(test_user.id)})
        ws = _StubWebSocket(headers={"sec-websocket-protocol": f"Bearer, {token}"})
        with patch("app.api.deps.decode_vf_session", return_value=None):
            user = await get_current_user_websocket(ws, test_session)
        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_no_cookie_no_token_returns_none(self, test_session, monkeypatch):
        _delegated(monkeypatch)
        from app.api.deps import get_current_user_websocket

        with patch("app.api.deps.decode_vf_session", return_value=None):
            user = await get_current_user_websocket(_StubWebSocket(), test_session)
        assert user is None

    @pytest.mark.asyncio
    async def test_bearer_wins_over_vf_cookie_when_both_present(
        self, test_session, test_user, monkeypatch
    ):
        """Bearer-first precedence: get_current_user_websocket must match
        get_current_user's HTTP precedence, where an explicit Authorization
        (bearer) credential always wins over the delegated VF cookie
        fallback. A valid Sec-WebSocket-Protocol bearer token plus a VF
        cookie resolving to a DIFFERENT user must resolve to the bearer
        user."""
        _delegated(monkeypatch)
        from app.api.deps import get_current_user_websocket
        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(test_user.id)})
        ws = _StubWebSocket(
            cookies={"authjs.session-token": "opaque-jwe"},
            headers={"sec-websocket-protocol": f"Bearer, {token}"},
        )
        with patch(
            "app.api.deps.decode_vf_session",
            return_value=_vf_claims(email="someone-else@example.com"),
        ):
            user = await get_current_user_websocket(ws, test_session)
        assert user is not None
        assert user.id == test_user.id
        assert user.email == "test@example.com"


class TestDelegatedModeGating:
    """CHAD-local auth surfaces read as nonexistent (404) in delegated mode —
    the CHAD_DELEGATED_AUTH twin of the sso_only seam (config.py:62)."""

    GATED = [
        ("post", "/api/auth/setup",
         {"admin_email": "a@b.co", "admin_password": "Str0ng!Passw0rd9"}),
        ("post", "/api/auth/login", {"email": "a@b.co", "password": "x"}),
        ("post", "/api/auth/login/2fa", {"token": "t", "code": "000000"}),
        ("post", "/api/auth/2fa/setup", {}),
        ("post", "/api/auth/2fa/verify", {"code": "000000"}),
        ("post", "/api/auth/2fa/disable", {"code": "000000"}),
        ("post", "/api/auth/sso/providers",
         {"name": "x", "client_id": "y", "issuer_url": "https://idp.example.com"}),
    ]

    @pytest.mark.asyncio
    async def test_gated_routes_404_in_delegated_mode(self, client, monkeypatch):
        _delegated(monkeypatch)
        for method, path, payload in self.GATED:
            # Any "Bearer ..." header makes CSRFMiddleware (csrf.py:205-227)
            # skip the double-submit check, so the request reaches routing;
            # the 404 gate is a route dependency and fires before auth runs.
            resp = await getattr(client, method)(
                path, json=payload, headers={"Authorization": "Bearer x"}
            )
            assert resp.status_code == 404, f"{path} -> {resp.status_code}"

    @pytest.mark.asyncio
    async def test_sso_provider_update_delete_gated(self, client, monkeypatch):
        _delegated(monkeypatch)
        pid = uuid.uuid4()
        resp = await client.put(
            f"/api/auth/sso/providers/{pid}", json={"name": "x"},
            headers={"Authorization": "Bearer x"},
        )
        assert resp.status_code == 404
        resp = await client.delete(
            f"/api/auth/sso/providers/{pid}", headers={"Authorization": "Bearer x"}
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_login_still_live_in_standalone_mode(self, client):
        resp = await client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401  # route exists; credentials rejected


class TestDelegatedFlagExposure:
    @pytest.mark.asyncio
    async def test_setup_status_exposes_flag_off(self, client):
        resp = await client.get("/api/auth/setup-status")
        assert resp.status_code == 200
        assert resp.json()["chad_delegated_auth"] is False

    @pytest.mark.asyncio
    async def test_setup_status_exposes_flag_on(self, client, monkeypatch):
        _delegated(monkeypatch)
        resp = await client.get("/api/auth/setup-status")
        assert resp.status_code == 200
        assert resp.json()["chad_delegated_auth"] is True

    @pytest.mark.asyncio
    async def test_auth_me_exposes_flag(self, client, monkeypatch):
        _delegated(monkeypatch)
        with patch("app.api.deps.decode_vf_session", return_value=_vf_claims()):
            resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["chad_delegated_auth"] is True
