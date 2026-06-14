"""Security-hardening tests for the SSO callback.

Covers:
  - first SSO user is NOT auto-admin (setup wizard owns the first admin)
  - claims come from a VALIDATED source only (no raw id_token fallback)
  - a malformed/non-UUID ?provider= is a clean redirect, never a 500
  - reconcile role authority: existing admin with empty groups keeps admin;
    group->admin promotion is audited
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.sso_provider import SSOGroupMapping, SSOProvider
from app.models.team import Team
from app.models.user import AuthMethod, ProvisionedVia, TeamSource, User, UserRole


async def _make_provider(db: AsyncSession, **overrides) -> SSOProvider:
    provider = SSOProvider(
        id=uuid.uuid4(),
        name=overrides.get("name", "Acme IdP"),
        enabled=True,
        issuer_url=overrides.get("issuer_url", "https://idp.example.com"),
        client_id="client-123",
        client_secret_encrypted=None,
        require_email_verified=overrides.get("require_email_verified", True),
        default_role=overrides.get("default_role", "viewer"),
        role_claim=overrides.get("role_claim"),
        admin_values=overrides.get("admin_values"),
        group_sync_enabled=overrides.get("group_sync_enabled", False),
        groups_claim=overrides.get("groups_claim"),
    )
    # Attach mappings BEFORE the first flush so the collection is never
    # lazy-loaded (which would trigger greenlet IO in async tests).
    for gv, team_id, role in overrides.get("mappings", []):
        provider.group_mappings.append(
            SSOGroupMapping(group_value=gv, team_id=team_id, role=role)
        )
    db.add(provider)
    await db.commit()

    # Re-load with mappings eager-loaded, mirroring the callback's selectinload.
    from sqlalchemy.orm import selectinload

    provider = (
        await db.execute(
            select(SSOProvider)
            .options(selectinload(SSOProvider.group_mappings))
            .where(SSOProvider.id == provider.id)
        )
    ).scalar_one()
    return provider


async def _call_callback(token, provider_id, db, *, userinfo_endpoint=None):
    from app.api import auth

    request = MagicMock()
    request.query_params = {"provider": str(provider_id)}

    fake_client = MagicMock()
    fake_client.authorize_access_token = AsyncMock(return_value=token)
    if userinfo_endpoint is not None:
        fake_client.userinfo = AsyncMock(return_value=userinfo_endpoint)

    with (
        patch.object(auth, "get_provider_client", new=MagicMock(return_value=fake_client)),
        patch.object(auth, "get_client_ip", new=MagicMock(return_value="1.2.3.4")),
    ):
        return await auth.sso_callback(request, db)


class TestNoFirstUserAdmin:
    @pytest.mark.asyncio
    async def test_first_sso_user_is_not_admin(self, test_session: AsyncSession):
        # Empty user table; SSO-created user must get provider default, not admin.
        provider = await _make_provider(test_session, default_role="analyst")
        resp = await _call_callback(
            {"userinfo": {"email": "first@example.com", "email_verified": True}},
            provider.id,
            test_session,
        )
        assert "sso_code" in resp.headers["location"]
        user = (
            await test_session.execute(
                select(User).where(User.email == "first@example.com")
            )
        ).scalar_one()
        assert user.role == UserRole.ANALYST  # NOT admin
        assert user.provisioned_via == ProvisionedVia.SSO.value


class TestValidatedClaimsOnly:
    @pytest.mark.asyncio
    async def test_no_validated_userinfo_fails(self, test_session: AsyncSession):
        # token has only a raw (unverified) id_token string and no userinfo;
        # userinfo endpoint also yields nothing -> login fails (no user created).
        provider = await _make_provider(test_session)
        resp = await _call_callback(
            {"id_token": "eyJhbGciOiJ.unverified.jwt"},  # must NOT be trusted
            provider.id,
            test_session,
            userinfo_endpoint={},  # endpoint returns no email
        )
        assert "login" in resp.headers["location"]
        assert "sso_code" not in resp.headers["location"]
        # No account fabricated from an unverified id_token.
        assert (
            await test_session.execute(select(User))
        ).scalars().first() is None

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_is_a_valid_source(self, test_session: AsyncSession):
        # No id-token userinfo, but the UserInfo endpoint returns a verified email.
        provider = await _make_provider(test_session)
        resp = await _call_callback(
            {"access_token": "at"},  # no "userinfo" key
            provider.id,
            test_session,
            userinfo_endpoint={"email": "fromuserinfo@example.com", "email_verified": True},
        )
        assert "sso_code" in resp.headers["location"]
        assert (
            await test_session.execute(
                select(User).where(User.email == "fromuserinfo@example.com")
            )
        ).scalar_one_or_none() is not None


class TestMalformedProvider:
    @pytest.mark.asyncio
    async def test_non_uuid_provider_is_clean_redirect(self, test_session: AsyncSession):
        from app.api import auth

        request = MagicMock()
        request.query_params = {"provider": "not-a-uuid'; DROP TABLE users;--"}
        with patch.object(auth, "get_client_ip", new=MagicMock(return_value="1.2.3.4")):
            resp = await auth.sso_callback(request, test_session)
        # Clean error redirect, not a 500.
        assert resp.status_code in (302, 307)
        assert "login" in resp.headers["location"]
        assert "sso_error" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_non_uuid_provider_login_is_400_not_500(self, test_session: AsyncSession):
        from fastapi import HTTPException

        from app.api import auth

        request = MagicMock()
        with pytest.raises(HTTPException) as exc:
            await auth.sso_login(request, test_session, provider_id="@@@not-uuid@@@")
        assert exc.value.status_code == 400


class TestReconcileRoleAuthority:
    @pytest.mark.asyncio
    async def test_existing_admin_empty_groups_keeps_admin(
        self, test_session: AsyncSession
    ):
        team = Team(id=uuid.uuid4(), name="SOC")
        test_session.add(team)
        await test_session.flush()
        provider = await _make_provider(
            test_session,
            group_sync_enabled=True,
            groups_claim="groups",
            default_role="viewer",
            mappings=[("soc-admins", team.id, "admin")],
        )
        admin = User(
            id=uuid.uuid4(), email="admin@example.com", password_hash=None,
            role=UserRole.ADMIN, auth_method=AuthMethod.SSO,
            provisioned_via=ProvisionedVia.SSO.value, is_active=True,
        )
        test_session.add(admin)
        await test_session.commit()

        # Login with an EMPTY groups claim — must not demote the admin.
        resp = await _call_callback(
            {"userinfo": {"email": "admin@example.com", "email_verified": True, "groups": []}},
            provider.id,
            test_session,
        )
        assert "sso_code" in resp.headers["location"]
        await test_session.refresh(admin)
        assert admin.role == UserRole.ADMIN

    @pytest.mark.asyncio
    async def test_group_admin_promotion_is_audited(self, test_session: AsyncSession):
        team = Team(id=uuid.uuid4(), name="SOC")
        test_session.add(team)
        await test_session.flush()
        provider = await _make_provider(
            test_session,
            group_sync_enabled=True,
            groups_claim="groups",
            default_role="viewer",
            mappings=[("soc-admins", team.id, "admin")],
        )
        # Pre-existing viewer who will be promoted via group.
        viewer = User(
            id=uuid.uuid4(), email="promote@example.com", password_hash=None,
            role=UserRole.VIEWER, auth_method=AuthMethod.SSO,
            provisioned_via=ProvisionedVia.SSO.value, is_active=True,
            team_source=TeamSource.GROUP_MAPPING.value,
        )
        test_session.add(viewer)
        await test_session.commit()

        resp = await _call_callback(
            {"userinfo": {
                "email": "promote@example.com", "email_verified": True,
                "groups": ["soc-admins"],
            }},
            provider.id,
            test_session,
        )
        assert "sso_code" in resp.headers["location"]
        await test_session.refresh(viewer)
        assert viewer.role == UserRole.ADMIN

        # The privileged promotion emitted an audit row.
        rows = (
            await test_session.execute(
                select(AuditLog).where(AuditLog.action == "sso.group_admin_granted")
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].resource_id == str(viewer.id)
