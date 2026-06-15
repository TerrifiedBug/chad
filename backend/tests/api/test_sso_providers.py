"""Tests for multi-provider OIDC: provider CRUD, secret masking, status, test-connection."""

import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.sso_provider import SSOProvider


def _payload(**overrides):
    body = {
        "name": "Acme IdP",
        "enabled": True,
        "issuer_url": "https://idp.example.com",
        "client_id": "client-abc",
        "client_secret": "super-secret-value",
        "default_role": "viewer",
        "require_email_verified": True,
    }
    body.update(overrides)
    return body


class TestProviderCrud:
    @pytest.mark.asyncio
    async def test_create_provider_masks_secret(self, authenticated_client: AsyncClient):
        resp = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["name"] == "Acme IdP"
        # Secret is write-only: never echoed; only a boolean flag is exposed.
        assert "client_secret" not in data
        assert "client_secret_encrypted" not in data
        assert data["client_secret_set"] is True

    @pytest.mark.asyncio
    async def test_secret_stored_encrypted_not_plaintext(
        self, authenticated_client: AsyncClient, test_session
    ):
        resp = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        pid = resp.json()["id"]
        provider = (
            await test_session.execute(
                select(SSOProvider).where(SSOProvider.id == uuid.UUID(pid))
            )
        ).scalar_one()
        assert provider.client_secret_encrypted
        assert provider.client_secret_encrypted != "super-secret-value"

    @pytest.mark.asyncio
    async def test_list_and_get(self, authenticated_client: AsyncClient):
        await authenticated_client.post("/api/auth/sso/providers", json=_payload())
        listed = await authenticated_client.get("/api/auth/sso/providers")
        assert listed.status_code == 200
        assert any(p["name"] == "Acme IdP" for p in listed.json())

        pid = listed.json()[0]["id"]
        got = await authenticated_client.get(f"/api/auth/sso/providers/{pid}")
        assert got.status_code == 200
        assert got.json()["id"] == pid

    @pytest.mark.asyncio
    async def test_update_without_secret_preserves_it(
        self, authenticated_client: AsyncClient, test_session
    ):
        created = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        pid = created.json()["id"]
        before = (
            await test_session.execute(
                select(SSOProvider).where(SSOProvider.id == uuid.UUID(pid))
            )
        ).scalar_one()
        old_secret = before.client_secret_encrypted

        # Update name only; omit client_secret -> secret preserved.
        resp = await authenticated_client.put(
            f"/api/auth/sso/providers/{pid}", json={"name": "Renamed"}
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed"
        assert resp.json()["client_secret_set"] is True

        test_session.expire_all()
        after = (
            await test_session.execute(
                select(SSOProvider).where(SSOProvider.id == uuid.UUID(pid))
            )
        ).scalar_one()
        assert after.client_secret_encrypted == old_secret

    @pytest.mark.asyncio
    async def test_group_mappings_round_trip(self, authenticated_client: AsyncClient):
        body = _payload(
            group_sync_enabled=True,
            groups_claim="groups",
            group_mappings=[
                {"group_value": "soc-admins", "team_id": None, "role": "admin"},
                {"group_value": "soc-viewers", "team_id": None, "role": "viewer"},
            ],
        )
        resp = await authenticated_client.post("/api/auth/sso/providers", json=body)
        assert resp.status_code == 201, resp.text
        mappings = resp.json()["group_mappings"]
        assert {m["group_value"] for m in mappings} == {"soc-admins", "soc-viewers"}

    @pytest.mark.asyncio
    async def test_delete_provider(self, authenticated_client: AsyncClient):
        created = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        pid = created.json()["id"]
        resp = await authenticated_client.delete(f"/api/auth/sso/providers/{pid}")
        assert resp.status_code == 204
        got = await authenticated_client.get(f"/api/auth/sso/providers/{pid}")
        assert got.status_code == 404

    @pytest.mark.asyncio
    async def test_duplicate_name_conflict(self, authenticated_client: AsyncClient):
        await authenticated_client.post("/api/auth/sso/providers", json=_payload())
        resp = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_non_admin_cannot_manage(self, client: AsyncClient, normal_token: str):
        resp = await client.post(
            "/api/auth/sso/providers",
            json=_payload(),
            headers={"Authorization": f"Bearer {normal_token}"},
        )
        assert resp.status_code == 403


class TestSsoStatus:
    @pytest.mark.asyncio
    async def test_status_lists_enabled_providers(self, client: AsyncClient, test_session):
        enabled = SSOProvider(
            id=uuid.uuid4(), name="Enabled IdP", enabled=True,
            issuer_url="https://a", client_id="a",
        )
        disabled = SSOProvider(
            id=uuid.uuid4(), name="Disabled IdP", enabled=False,
            issuer_url="https://b", client_id="b",
        )
        test_session.add_all([enabled, disabled])
        await test_session.commit()

        resp = await client.get("/api/auth/sso/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        names = {p["name"] for p in data["providers"]}
        assert "Enabled IdP" in names
        assert "Disabled IdP" not in names
        assert "sso_enforced" in data

    @pytest.mark.asyncio
    async def test_status_empty_when_no_providers(self, client: AsyncClient):
        resp = await client.get("/api/auth/sso/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is False
        assert data["providers"] == []


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_test_connection_success(
        self, authenticated_client: AsyncClient, test_session
    ):
        created = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        pid = created.json()["id"]

        async def fake_probe(issuer_url, timeout=8.0):
            return True, "Discovery document is valid", {
                "authorization_endpoint": "https://idp/auth",
                "token_endpoint": "https://idp/token",
                "jwks_uri": "https://idp/jwks",
            }

        with patch("app.api.sso.probe_oidc_discovery", new=fake_probe):
            resp = await authenticated_client.post(
                f"/api/auth/sso/providers/{pid}/test", json={}
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        test_session.expire_all()
        provider = (
            await test_session.execute(
                select(SSOProvider).where(SSOProvider.id == uuid.UUID(pid))
            )
        ).scalar_one()
        assert provider.last_test_success is True
        assert provider.last_tested_at is not None

    @pytest.mark.asyncio
    async def test_test_connection_failure(
        self, authenticated_client: AsyncClient, test_session
    ):
        created = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload()
        )
        pid = created.json()["id"]

        async def fake_probe(issuer_url, timeout=8.0):
            return False, "Discovery endpoint returned HTTP 404", {}

        with patch("app.api.sso.probe_oidc_discovery", new=fake_probe):
            resp = await authenticated_client.post(
                f"/api/auth/sso/providers/{pid}/test", json={}
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is False

        test_session.expire_all()
        provider = (
            await test_session.execute(
                select(SSOProvider).where(SSOProvider.id == uuid.UUID(pid))
            )
        ).scalar_one()
        assert provider.last_test_success is False


class TestProbeSsrf:
    @pytest.mark.asyncio
    async def test_probe_rejects_non_https(self):
        from app.services.sso_providers import probe_oidc_discovery

        ok, msg, _ = await probe_oidc_discovery("http://idp.example.com")
        assert ok is False
        assert "https" in msg.lower()

    @pytest.mark.asyncio
    async def test_probe_rejects_private_ip(self):
        from app.core.config import settings
        from app.services.sso_providers import probe_oidc_discovery

        # Cloud metadata endpoint must be refused before any network call. Force
        # the SSRF guard on (the dev/test env may set ALLOW_INTERNAL_WEBHOOK_IPS).
        with patch.object(settings, "ALLOW_INTERNAL_WEBHOOK_IPS", False):
            ok, msg, _ = await probe_oidc_discovery("https://169.254.169.254")
        assert ok is False

    @pytest.mark.asyncio
    async def test_probe_does_not_follow_redirects(self):
        # follow_redirects must be False so a 302 -> metadata IP can't bypass the
        # pre-flight host check.
        import inspect

        from app.services import sso_providers

        src = inspect.getsource(sso_providers.probe_oidc_discovery)
        assert "follow_redirects=False" in src


class TestProviderCreateSsrf:
    @pytest.mark.asyncio
    async def test_create_rejects_non_https_issuer(self, authenticated_client: AsyncClient):
        resp = await authenticated_client.post(
            "/api/auth/sso/providers", json=_payload(issuer_url="http://idp.example.com")
        )
        assert resp.status_code == 400
        assert "issuer" in resp.text.lower()

    @pytest.mark.asyncio
    async def test_create_allows_internal_ip_issuer(self, authenticated_client: AsyncClient):
        # Per validate_issuer_url (sso_providers.py): the issuer is admin-set, not
        # attacker-supplied, and self-hosted IdPs (Authentik/Keycloak/PocketID) legitimately
        # live on private networks — internal IPs are intentionally PERMITTED; only https is required.
        resp = await authenticated_client.post(
            "/api/auth/sso/providers",
            json=_payload(issuer_url="https://169.254.169.254"),
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_build_client_allows_internal_issuer(self, test_session):
        # The login-path client builder accepts internal-IP issuers for the same reason
        # validate_issuer_url permits them: admin-set self-hosted IdPs on private networks.
        from app.models.sso_provider import SSOProvider
        from app.services.sso_providers import build_provider_client

        provider = SSOProvider(
            id=uuid.uuid4(), name="Self-hosted IdP", enabled=True,
            issuer_url="https://127.0.0.1", client_id="c",
        )
        # Should not raise.
        build_provider_client(provider)


class TestSsoEnforcement:
    @pytest.mark.asyncio
    async def test_get_defaults_false(self, authenticated_client: AsyncClient):
        resp = await authenticated_client.get("/api/auth/sso/enforcement")
        assert resp.status_code == 200
        assert resp.json()["sso_enforced"] is False

    @pytest.mark.asyncio
    async def test_put_then_get_round_trips(self, authenticated_client: AsyncClient):
        put = await authenticated_client.put(
            "/api/auth/sso/enforcement", json={"sso_enforced": True}
        )
        assert put.status_code == 200
        assert put.json()["sso_enforced"] is True

        got = await authenticated_client.get("/api/auth/sso/enforcement")
        assert got.json()["sso_enforced"] is True

        # And it can be turned back off.
        off = await authenticated_client.put(
            "/api/auth/sso/enforcement", json={"sso_enforced": False}
        )
        assert off.json()["sso_enforced"] is False
        again = await authenticated_client.get("/api/auth/sso/enforcement")
        assert again.json()["sso_enforced"] is False

    @pytest.mark.asyncio
    async def test_enforcement_reflected_in_status(
        self, authenticated_client: AsyncClient, client: AsyncClient
    ):
        await authenticated_client.put(
            "/api/auth/sso/enforcement", json={"sso_enforced": True}
        )
        status_resp = await client.get("/api/auth/sso/status")
        assert status_resp.json()["sso_enforced"] is True

    @pytest.mark.asyncio
    async def test_put_preserves_other_sso_settings(
        self, authenticated_client: AsyncClient, test_session
    ):
        # An existing sso setting (e.g. a legacy client_secret) must survive a
        # toggle of the enforcement flag.
        from app.services.settings import get_setting, set_setting

        await set_setting(
            test_session, "sso", {"client_secret": "keep-me", "sso_only": False}
        )
        await authenticated_client.put(
            "/api/auth/sso/enforcement", json={"sso_enforced": True}
        )
        test_session.expire_all()
        cfg = await get_setting(test_session, "sso")
        assert cfg["client_secret"] == "keep-me"
        assert cfg["sso_only"] is True

    @pytest.mark.asyncio
    async def test_get_requires_admin(self, client: AsyncClient, normal_token: str):
        resp = await client.get(
            "/api/auth/sso/enforcement",
            headers={"Authorization": f"Bearer {normal_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_put_requires_admin(self, client: AsyncClient, normal_token: str):
        resp = await client.put(
            "/api/auth/sso/enforcement",
            json={"sso_enforced": True},
            headers={"Authorization": f"Bearer {normal_token}"},
        )
        assert resp.status_code == 403
