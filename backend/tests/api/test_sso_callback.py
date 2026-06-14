"""Tests for the SSO callback email-verification gate (account-takeover defense).

Multi-provider flow: the callback resolves an enabled ``SSOProvider`` row and
builds a per-provider Authlib client. These tests stub the discovery/token
exchange and assert the email_verified gate still holds.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sso_provider import SSOProvider
from app.models.user import User


async def _make_provider(db: AsyncSession, **overrides) -> SSOProvider:
    provider = SSOProvider(
        id=uuid.uuid4(),
        name=overrides.get("name", "Acme IdP"),
        enabled=True,
        issuer_url="https://idp.example.com",
        client_id="client-123",
        client_secret_encrypted=None,
        require_email_verified=overrides.get("require_email_verified", True),
        default_role=overrides.get("default_role", "viewer"),
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return provider


async def _call_callback(token_userinfo, provider, db):
    from app.api import auth

    request = MagicMock()
    request.query_params = {"provider": str(provider.id)}

    fake_client = MagicMock()
    fake_client.authorize_access_token = AsyncMock(
        return_value={"userinfo": token_userinfo}
    )

    with (
        patch.object(auth, "get_provider_client", new=MagicMock(return_value=fake_client)),
        patch.object(auth, "get_client_ip", new=MagicMock(return_value="1.2.3.4")),
    ):
        return await auth.sso_callback(request, db)


class TestSsoEmailVerificationGate:
    @pytest.mark.asyncio
    async def test_unverified_email_rejected_and_no_user_created(
        self, test_session: AsyncSession
    ):
        provider = await _make_provider(test_session)
        resp = await _call_callback(
            {"email": "attacker@victim.com", "email_verified": False},
            provider,
            test_session,
        )
        # Redirected back to login with a verification error.
        assert "login" in resp.headers["location"]
        assert "verified" in resp.headers["location"]
        # No account was created/looked-up off an unverified email.
        result = await test_session.execute(
            select(User).where(User.email == "attacker@victim.com")
        )
        assert result.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_missing_email_verified_claim_rejected_by_default(
        self, test_session: AsyncSession
    ):
        provider = await _make_provider(test_session)
        resp = await _call_callback(
            {"email": "noclaim@example.com"},  # no email_verified at all
            provider,
            test_session,
        )
        assert "verified" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_opt_out_allows_unverified(self, test_session: AsyncSession):
        # Operators whose IdP omits the claim can opt out; then a user is created.
        provider = await _make_provider(test_session, require_email_verified=False)
        resp = await _call_callback(
            {"email": "trusted@example.com"},
            provider,
            test_session,
        )
        # Proceeds past the gate -> redirects with an sso_code, user created.
        assert "sso_code" in resp.headers["location"]
        result = await test_session.execute(
            select(User).where(User.email == "trusted@example.com")
        )
        assert result.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_verified_email_string_true_accepted(self, test_session: AsyncSession):
        provider = await _make_provider(test_session)
        resp = await _call_callback(
            {"email": "verified@example.com", "email_verified": "true"},
            provider,
            test_session,
        )
        assert "sso_code" in resp.headers["location"]
        result = await test_session.execute(
            select(User).where(User.email == "verified@example.com")
        )
        assert result.scalar_one_or_none() is not None
