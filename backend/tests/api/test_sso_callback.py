"""Tests for the SSO callback email-verification gate (account-takeover defense)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


def _sso_config(**overrides):
    cfg = {"enabled": True, "default_role": "analyst"}
    cfg.update(overrides)
    return cfg


async def _call_callback(token_userinfo, sso_config, db):
    from app.api import auth

    request = MagicMock()
    with (
        patch.object(auth, "get_setting", new=AsyncMock(return_value=sso_config)),
        patch.object(auth, "_register_oauth_client", new=MagicMock()),
        patch.object(auth, "get_client_ip", new=MagicMock(return_value="1.2.3.4")),
        patch.object(auth, "oauth") as mock_oauth,
    ):
        mock_oauth.oidc.authorize_access_token = AsyncMock(
            return_value={"userinfo": token_userinfo}
        )
        return await auth.sso_callback(request, db)


class TestSsoEmailVerificationGate:
    @pytest.mark.asyncio
    async def test_unverified_email_rejected_and_no_user_created(
        self, test_session: AsyncSession
    ):
        resp = await _call_callback(
            {"email": "attacker@victim.com", "email_verified": False},
            _sso_config(),
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
        resp = await _call_callback(
            {"email": "noclaim@example.com"},  # no email_verified at all
            _sso_config(),
            test_session,
        )
        assert "verified" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_opt_out_allows_unverified(self, test_session: AsyncSession):
        # Operators whose IdP omits the claim can opt out; then a user is created.
        resp = await _call_callback(
            {"email": "trusted@example.com"},
            _sso_config(require_email_verified=False),
            test_session,
        )
        # Proceeds past the gate → redirects with an sso_code, user created.
        assert "sso_code" in resp.headers["location"]
        result = await test_session.execute(
            select(User).where(User.email == "trusted@example.com")
        )
        assert result.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_verified_email_string_true_accepted(self, test_session: AsyncSession):
        resp = await _call_callback(
            {"email": "verified@example.com", "email_verified": "true"},
            _sso_config(),
            test_session,
        )
        assert "sso_code" in resp.headers["location"]
        result = await test_session.execute(
            select(User).where(User.email == "verified@example.com")
        )
        assert result.scalar_one_or_none() is not None
