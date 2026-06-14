"""C1: refuse silent LOCAL->SSO account fusion (account-takeover defense)."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.sso_provider import SSOProvider
from app.models.user import AuthMethod, ProvisionedVia, User, UserRole


async def _make_provider(db: AsyncSession) -> SSOProvider:
    provider = SSOProvider(
        id=uuid.uuid4(), name="IdP", enabled=True,
        issuer_url="https://idp", client_id="c",
        require_email_verified=True, default_role="viewer",
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return provider


async def _callback(userinfo, provider, db):
    from app.api import auth

    request = MagicMock()
    request.query_params = {"provider": str(provider.id)}
    fake_client = MagicMock()
    fake_client.authorize_access_token = AsyncMock(return_value={"userinfo": userinfo})
    with (
        patch.object(auth, "get_provider_client", new=MagicMock(return_value=fake_client)),
        patch.object(auth, "get_client_ip", new=MagicMock(return_value="1.2.3.4")),
    ):
        return await auth.sso_callback(request, db)


class TestLocalToSsoFusionRefused:
    @pytest.mark.asyncio
    async def test_local_account_match_is_refused(self, test_session: AsyncSession):
        local = User(
            id=uuid.uuid4(),
            email="alice@example.com",
            password_hash=get_password_hash("a-strong-password-123"),
            role=UserRole.ADMIN,
            auth_method=AuthMethod.LOCAL,
            provisioned_via=ProvisionedVia.LOCAL.value,
            is_active=True,
        )
        test_session.add(local)
        await test_session.commit()

        provider = await _make_provider(test_session)
        resp = await _callback(
            {"email": "alice@example.com", "email_verified": True}, provider, test_session
        )

        # Refused: redirected to login with an error, NOT issued an sso_code.
        assert "login" in resp.headers["location"]
        assert "sso_code" not in resp.headers["location"]

        await test_session.refresh(local)
        # Password + provenance + auth_method are all untouched (no silent convert).
        assert local.password_hash is not None
        assert local.provisioned_via == ProvisionedVia.LOCAL.value
        assert local.auth_method == AuthMethod.LOCAL

    @pytest.mark.asyncio
    async def test_existing_sso_user_still_logs_in(self, test_session: AsyncSession):
        sso_user = User(
            id=uuid.uuid4(),
            email="bob@example.com",
            password_hash=None,
            role=UserRole.ANALYST,
            auth_method=AuthMethod.SSO,
            provisioned_via=ProvisionedVia.SSO.value,
            is_active=True,
        )
        test_session.add(sso_user)
        await test_session.commit()

        provider = await _make_provider(test_session)
        resp = await _callback(
            {"email": "bob@example.com", "email_verified": True}, provider, test_session
        )
        # SSO -> SSO continues normally.
        assert "sso_code" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_new_sso_user_gets_sso_provenance(self, test_session: AsyncSession):
        provider = await _make_provider(test_session)
        resp = await _callback(
            {"email": "carol@example.com", "email_verified": True}, provider, test_session
        )
        assert "sso_code" in resp.headers["location"]
        user = (
            await test_session.execute(
                select(User).where(User.email == "carol@example.com")
            )
        ).scalar_one()
        assert user.provisioned_via == ProvisionedVia.SSO.value
        assert user.auth_method == AuthMethod.SSO
