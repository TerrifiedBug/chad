"""SCIM 2.0 Users: bearer auth, ServiceProviderConfig, CRUD, filters, coexistence guards."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.setting import Setting
from app.models.user import AuthMethod, ProvisionedVia, User, UserRole
from app.services.scim import generate_scim_token, set_scim_enabled


async def _enable_scim(test_session) -> str:
    token = await generate_scim_token(test_session)
    await set_scim_enabled(test_session, True)
    await test_session.commit()
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _scim_user_body(username, **overrides):
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "active": True,
    }
    body.update(overrides)
    return body


class TestScimAuth:
    @pytest.mark.asyncio
    async def test_disabled_returns_403(self, client: AsyncClient, test_session):
        # SCIM not enabled -> 403 regardless of token.
        resp = await client.get(
            "/api/scim/v2/ServiceProviderConfig", headers=_auth("anything")
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_wrong_token_401(self, client: AsyncClient, test_session):
        await _enable_scim(test_session)
        resp = await client.get(
            "/api/scim/v2/ServiceProviderConfig", headers=_auth("wrong-token")
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_bearer_401(self, client: AsyncClient, test_session):
        await _enable_scim(test_session)
        resp = await client.get("/api/scim/v2/ServiceProviderConfig")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_200(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        resp = await client.get(
            "/api/scim/v2/ServiceProviderConfig", headers=_auth(token)
        )
        assert resp.status_code == 200


class TestServiceProviderConfig:
    @pytest.mark.asyncio
    async def test_capabilities(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        resp = await client.get(
            "/api/scim/v2/ServiceProviderConfig", headers=_auth(token)
        )
        data = resp.json()
        assert data["patch"]["supported"] is True
        assert data["bulk"]["supported"] is False
        assert data["filter"]["supported"] is True
        assert data["sort"]["supported"] is False


class TestScimUserLifecycle:
    @pytest.mark.asyncio
    async def test_create_marks_provenance(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        resp = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("newuser@example.com", externalId="ext-1"),
            headers=_auth(token),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["userName"] == "newuser@example.com"
        assert body["externalId"] == "ext-1"

        user = (
            await test_session.execute(
                select(User).where(User.email == "newuser@example.com")
            )
        ).scalar_one()
        assert user.provisioned_via == ProvisionedVia.SCIM.value
        assert user.scim_external_id == "ext-1"

    @pytest.mark.asyncio
    async def test_get_and_list(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        created = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("a@example.com"),
            headers=_auth(token),
        )
        uid = created.json()["id"]

        got = await client.get(f"/api/scim/v2/Users/{uid}", headers=_auth(token))
        assert got.status_code == 200
        assert got.json()["id"] == uid

        listed = await client.get("/api/scim/v2/Users", headers=_auth(token))
        assert listed.status_code == 200
        assert listed.json()["totalResults"] >= 1

    @pytest.mark.asyncio
    async def test_filter_username_eq(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("findme@example.com"),
            headers=_auth(token),
        )
        await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("other@example.com"),
            headers=_auth(token),
        )
        resp = await client.get(
            '/api/scim/v2/Users?filter=userName eq "findme@example.com"',
            headers=_auth(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["totalResults"] == 1
        assert data["Resources"][0]["userName"] == "findme@example.com"

    @pytest.mark.asyncio
    async def test_unsupported_filter_400(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        resp = await client.get(
            '/api/scim/v2/Users?filter=userName co "x"', headers=_auth(token)
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_patch_deactivate(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        created = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("patchme@example.com"),
            headers=_auth(token),
        )
        uid = created.json()["id"]

        patch_body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": False}],
        }
        resp = await client.patch(
            f"/api/scim/v2/Users/{uid}", json=patch_body, headers=_auth(token)
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    @pytest.mark.asyncio
    async def test_delete_deactivates(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        created = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("delme@example.com"),
            headers=_auth(token),
        )
        uid = created.json()["id"]
        resp = await client.delete(f"/api/scim/v2/Users/{uid}", headers=_auth(token))
        assert resp.status_code == 204

        user = (
            await test_session.execute(select(User).where(User.id == uuid.UUID(uid)))
        ).scalar_one()
        assert user.is_active is False


class TestCoexistenceGuards:
    @pytest.mark.asyncio
    async def test_cannot_create_over_local_user(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        local = User(
            id=uuid.uuid4(), email="local@example.com",
            password_hash="x", role=UserRole.VIEWER,
            auth_method=AuthMethod.LOCAL, provisioned_via=ProvisionedVia.LOCAL.value,
            is_active=True,
        )
        test_session.add(local)
        await test_session.commit()

        resp = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("local@example.com"),
            headers=_auth(token),
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_cannot_deactivate_local_user(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        local = User(
            id=uuid.uuid4(), email="local2@example.com",
            password_hash="x", role=UserRole.VIEWER,
            auth_method=AuthMethod.LOCAL, provisioned_via=ProvisionedVia.LOCAL.value,
            is_active=True,
        )
        test_session.add(local)
        await test_session.commit()

        resp = await client.delete(
            f"/api/scim/v2/Users/{local.id}", headers=_auth(token)
        )
        assert resp.status_code == 403
        await test_session.refresh(local)
        assert local.is_active is True

    @pytest.mark.asyncio
    async def test_cannot_deactivate_last_admin(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        # The ONLY active admin, but SCIM-provisioned.
        admin = User(
            id=uuid.uuid4(), email="scimadmin@example.com",
            password_hash=None, role=UserRole.ADMIN,
            auth_method=AuthMethod.SSO, provisioned_via=ProvisionedVia.SCIM.value,
            scim_external_id="admin-ext", is_active=True,
        )
        test_session.add(admin)
        await test_session.commit()

        resp = await client.delete(
            f"/api/scim/v2/Users/{admin.id}", headers=_auth(token)
        )
        assert resp.status_code == 403
        await test_session.refresh(admin)
        assert admin.is_active is True


class TestTokenManagement:
    @pytest.mark.asyncio
    async def test_generate_token_once_and_encrypted(
        self, authenticated_client: AsyncClient, test_session
    ):
        resp = await authenticated_client.post("/api/scim/token", json={})
        assert resp.status_code == 200
        token = resp.json()["token"]
        # 64-hex token.
        assert len(token) == 64
        int(token, 16)  # raises if not hex

        # Stored value is encrypted, never the plaintext token.
        setting = (
            await test_session.execute(select(Setting).where(Setting.key == "scim"))
        ).scalar_one()
        assert setting.value["bearer_token"] != token

    @pytest.mark.asyncio
    async def test_generate_token_requires_admin(
        self, client: AsyncClient, normal_token: str
    ):
        resp = await client.post(
            "/api/scim/token",
            json={},
            headers={"Authorization": f"Bearer {normal_token}"},
        )
        assert resp.status_code == 403


class TestScimConfig:
    @pytest.mark.asyncio
    async def test_config_defaults_disabled_no_token(
        self, authenticated_client: AsyncClient
    ):
        resp = await authenticated_client.get("/api/scim/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is False
        assert data["token_configured"] is False

    @pytest.mark.asyncio
    async def test_config_reflects_enabled_and_token(
        self, authenticated_client: AsyncClient, test_session
    ):
        # Generate a token (stored encrypted) and enable SCIM.
        await generate_scim_token(test_session)
        await set_scim_enabled(test_session, True)
        await test_session.commit()

        resp = await authenticated_client.get("/api/scim/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert data["token_configured"] is True

    @pytest.mark.asyncio
    async def test_config_requires_admin(self, client: AsyncClient, normal_token: str):
        resp = await client.get(
            "/api/scim/config", headers={"Authorization": f"Bearer {normal_token}"}
        )
        assert resp.status_code == 403


class TestScimEmailNormalization:
    @pytest.mark.asyncio
    async def test_create_lowercases_email(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        resp = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("MixedCase@Example.COM"),
            headers=_auth(token),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["userName"] == "mixedcase@example.com"
        user = (
            await test_session.execute(
                select(User).where(User.email == "mixedcase@example.com")
            )
        ).scalar_one()
        assert user.email == "mixedcase@example.com"

    @pytest.mark.asyncio
    async def test_put_lowercases_and_blocks_rename_onto_local(
        self, client: AsyncClient, test_session
    ):
        token = await _enable_scim(test_session)
        # A SCIM user we own.
        created = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("scimuser@example.com"),
            headers=_auth(token),
        )
        uid = created.json()["id"]
        # A pre-existing LOCAL user we must never seize by rename.
        local = User(
            id=uuid.uuid4(), email="victim@example.com", password_hash="x",
            role=UserRole.VIEWER, auth_method=AuthMethod.LOCAL,
            provisioned_via=ProvisionedVia.LOCAL.value, is_active=True,
        )
        test_session.add(local)
        await test_session.commit()

        resp = await client.put(
            f"/api/scim/v2/Users/{uid}",
            json=_scim_user_body("VICTIM@example.com"),  # rename onto local user
            headers=_auth(token),
        )
        assert resp.status_code == 409
        # The local user is untouched.
        await test_session.refresh(local)
        assert local.provisioned_via == ProvisionedVia.LOCAL.value

    @pytest.mark.asyncio
    async def test_patch_rename_onto_local_blocked(self, client: AsyncClient, test_session):
        token = await _enable_scim(test_session)
        created = await client.post(
            "/api/scim/v2/Users",
            json=_scim_user_body("patchrename@example.com"),
            headers=_auth(token),
        )
        uid = created.json()["id"]
        local = User(
            id=uuid.uuid4(), email="target@example.com", password_hash="x",
            role=UserRole.VIEWER, auth_method=AuthMethod.LOCAL,
            provisioned_via=ProvisionedVia.LOCAL.value, is_active=True,
        )
        test_session.add(local)
        await test_session.commit()

        patch_body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "userName", "value": "Target@Example.com"}],
        }
        resp = await client.patch(
            f"/api/scim/v2/Users/{uid}", json=patch_body, headers=_auth(token)
        )
        assert resp.status_code == 409


class TestScimTokenDecryptFailure:
    @pytest.mark.asyncio
    async def test_unreadable_token_fails_closed(self, test_session):
        # A corrupt/undecryptable stored token must be treated as unset (None),
        # never returned as ciphertext that could be used as a credential.
        from app.services.scim import get_scim_token_plaintext

        test_session.add(
            Setting(key="scim", value={"enabled": True, "bearer_token": "not-fernet-ciphertext"})
        )
        await test_session.commit()
        assert await get_scim_token_plaintext(test_session) is None
