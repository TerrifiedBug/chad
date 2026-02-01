"""Tests for 2FA authentication API endpoints."""

import uuid

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.services.totp import hash_backup_code


class TestSetup2FA:
    """Tests for POST /auth/2fa/setup endpoint."""

    @pytest.mark.asyncio
    async def test_2fa_setup_returns_qr_uri(
        self, authenticated_client: AsyncClient, test_user: User
    ):
        """2FA setup returns QR URI and secret."""
        response = await authenticated_client.post("/api/auth/2fa/setup", json={})
        assert response.status_code == 200
        data = response.json()
        assert "qr_uri" in data
        assert "secret" in data
        assert data["qr_uri"].startswith("otpauth://totp/")
        assert len(data["secret"]) == 32

    @pytest.mark.asyncio
    async def test_2fa_setup_fails_for_sso_user(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA setup fails for SSO users."""
        # Create an SSO user (no password_hash)
        sso_user = User(
            id=uuid.uuid4(),
            email="ssouser@example.com",
            password_hash=None,  # SSO user
            role=UserRole.ANALYST,
            is_active=True,
        )
        test_session.add(sso_user)
        await test_session.commit()

        # Create token for SSO user
        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(sso_user.id)})

        response = await client.post(
            "/api/auth/2fa/setup",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert "SSO" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_2fa_setup_fails_if_already_enabled(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA setup fails if already enabled."""
        user = User(
            id=uuid.uuid4(),
            email="2fauser@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret="JBSWY3DPEHPK3PXP",
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(user.id)})

        response = await client.post(
            "/api/auth/2fa/setup",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert "already enabled" in response.json()["detail"]


class TestVerify2FA:
    """Tests for POST /auth/2fa/verify endpoint."""

    @pytest.mark.asyncio
    async def test_2fa_verify_completes_setup(
        self, authenticated_client: AsyncClient, test_session: AsyncSession, test_user: User
    ):
        """2FA verify with valid code completes setup."""
        # First, initiate setup
        setup_response = await authenticated_client.post("/api/auth/2fa/setup")
        assert setup_response.status_code == 200
        secret = setup_response.json()["secret"]

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Verify with the code
        response = await authenticated_client.post(
            "/api/auth/2fa/verify",
            json={"code": code},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "2FA enabled successfully"
        assert "backup_codes" in data
        assert len(data["backup_codes"]) == 10

        # Verify user has 2FA enabled in database
        await test_session.refresh(test_user)
        assert test_user.totp_enabled is True
        assert test_user.totp_secret == secret

    @pytest.mark.asyncio
    async def test_2fa_verify_with_invalid_code_fails(
        self, authenticated_client: AsyncClient
    ):
        """2FA verify with invalid code fails."""
        # First, initiate setup
        setup_response = await authenticated_client.post("/api/auth/2fa/setup")
        assert setup_response.status_code == 200

        # Verify with wrong code
        response = await authenticated_client.post(
            "/api/auth/2fa/verify",
            json={"code": "000000"},
        )
        assert response.status_code == 400
        assert "Invalid" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_2fa_verify_without_setup_fails(
        self, authenticated_client: AsyncClient
    ):
        """2FA verify without prior setup fails."""
        response = await authenticated_client.post(
            "/api/auth/2fa/verify",
            json={"code": "123456"},
        )
        assert response.status_code == 400
        assert "No pending" in response.json()["detail"]


class TestDisable2FA:
    """Tests for POST /auth/2fa/disable endpoint."""

    @pytest.mark.asyncio
    async def test_2fa_disable_with_totp_code(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA disable with valid TOTP code succeeds."""
        secret = pyotp.random_base32()
        user = User(
            id=uuid.uuid4(),
            email="disable2fa@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(user.id)})

        totp = pyotp.TOTP(secret)
        code = totp.now()

        response = await client.post(
            "/api/auth/2fa/disable",
            json={"code": code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "2FA disabled"

        await test_session.refresh(user)
        assert user.totp_enabled is False
        assert user.totp_secret is None

    @pytest.mark.asyncio
    async def test_2fa_disable_with_backup_code(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA disable with valid backup code succeeds."""
        secret = pyotp.random_base32()
        backup_code = "ABCD1234"
        hashed_backup = hash_backup_code(backup_code)

        user = User(
            id=uuid.uuid4(),
            email="disablebackup@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
            totp_backup_codes=[hashed_backup],
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(user.id)})

        response = await client.post(
            "/api/auth/2fa/disable",
            json={"code": backup_code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "2FA disabled"

    @pytest.mark.asyncio
    async def test_2fa_disable_with_invalid_code_fails(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA disable with invalid code fails."""
        secret = pyotp.random_base32()
        user = User(
            id=uuid.uuid4(),
            email="invalidcode@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token

        token = create_access_token(data={"sub": str(user.id)})

        response = await client.post(
            "/api/auth/2fa/disable",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert "Invalid" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_2fa_disable_when_not_enabled_fails(
        self, authenticated_client: AsyncClient
    ):
        """2FA disable when not enabled fails."""
        response = await authenticated_client.post(
            "/api/auth/2fa/disable",
            json={"code": "123456"},
        )
        assert response.status_code == 400
        assert "not enabled" in response.json()["detail"]


class TestLogin2FA:
    """Tests for POST /auth/login/2fa endpoint."""

    @pytest.mark.asyncio
    async def test_login_with_2fa_returns_requires_2fa(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """Login with 2FA-enabled user returns requires_2fa."""
        secret = pyotp.random_base32()
        user = User(
            id=uuid.uuid4(),
            email="login2fa@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
        )
        test_session.add(user)
        await test_session.commit()

        response = await client.post(
            "/api/auth/login",
            json={"email": "login2fa@example.com", "password": "password123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["requires_2fa"] is True
        assert "2fa_token" in data

    @pytest.mark.asyncio
    async def test_2fa_login_with_valid_code_succeeds(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA login with valid code returns access token."""
        secret = pyotp.random_base32()
        user = User(
            id=uuid.uuid4(),
            email="complete2fa@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
        )
        test_session.add(user)
        await test_session.commit()

        # First login to get 2FA token
        login_response = await client.post(
            "/api/auth/login",
            json={"email": "complete2fa@example.com", "password": "password123"},
        )
        assert login_response.status_code == 200
        two_fa_token = login_response.json()["2fa_token"]

        # Complete 2FA login
        totp = pyotp.TOTP(secret)
        code = totp.now()

        response = await client.post(
            "/api/auth/login/2fa",
            json={"token": two_fa_token, "code": code},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_2fa_login_with_backup_code_succeeds(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA login with valid backup code returns access token."""
        secret = pyotp.random_base32()
        backup_code = "ABCD1234"
        hashed_backup = hash_backup_code(backup_code)

        user = User(
            id=uuid.uuid4(),
            email="backuplogin@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
            totp_backup_codes=[hashed_backup],
        )
        test_session.add(user)
        await test_session.commit()

        # First login to get 2FA token
        login_response = await client.post(
            "/api/auth/login",
            json={"email": "backuplogin@example.com", "password": "password123"},
        )
        two_fa_token = login_response.json()["2fa_token"]

        # Complete 2FA login with backup code
        response = await client.post(
            "/api/auth/login/2fa",
            json={"token": two_fa_token, "code": backup_code},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

        # Verify backup code was consumed
        await test_session.refresh(user)
        assert len(user.totp_backup_codes) == 0

    @pytest.mark.asyncio
    async def test_2fa_login_with_invalid_code_fails(
        self, client: AsyncClient, test_session: AsyncSession
    ):
        """2FA login with invalid code fails."""
        secret = pyotp.random_base32()
        user = User(
            id=uuid.uuid4(),
            email="invalid2fa@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
            totp_enabled=True,
            totp_secret=secret,
        )
        test_session.add(user)
        await test_session.commit()

        # First login to get 2FA token
        login_response = await client.post(
            "/api/auth/login",
            json={"email": "invalid2fa@example.com", "password": "password123"},
        )
        two_fa_token = login_response.json()["2fa_token"]

        # Try with invalid code
        response = await client.post(
            "/api/auth/login/2fa",
            json={"token": two_fa_token, "code": "000000"},
        )
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_2fa_login_with_invalid_token_fails(
        self, client: AsyncClient
    ):
        """2FA login with invalid token fails."""
        response = await client.post(
            "/api/auth/login/2fa",
            json={"token": "invalid_token", "code": "123456"},
        )
        assert response.status_code == 400
        assert "Invalid or expired" in response.json()["detail"]


class TestMe2FAStatus:
    """Tests for 2FA status in /auth/me endpoint."""

    @pytest.mark.asyncio
    async def test_me_includes_2fa_status(
        self, authenticated_client: AsyncClient, test_user: User
    ):
        """Test /auth/me includes 2FA status."""
        response = await authenticated_client.get("/api/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert "totp_enabled" in data
        assert data["totp_enabled"] is False
