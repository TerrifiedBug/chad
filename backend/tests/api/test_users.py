"""Tests for the users API endpoints."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.user import User, UserRole


class TestUpdateUser:
    """Tests for PATCH /users/{user_id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_user_role(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Update local user role succeeds."""
        # Create a local user to update
        user = User(
            id=uuid.uuid4(),
            email="localuser@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()

        response = await authenticated_client.patch(
            f"/api/users/{user.id}",
            json={"role": "analyst"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_update_user_is_active(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Update user is_active status succeeds."""
        # Create a user to deactivate
        user = User(
            id=uuid.uuid4(),
            email="deactivateuser@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.ANALYST,
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()

        response = await authenticated_client.patch(
            f"/api/users/{user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_nonexistent_user_returns_404(
        self, authenticated_client: AsyncClient
    ):
        """Update non-existent user returns 404."""
        fake_user_id = uuid.uuid4()
        response = await authenticated_client.patch(
            f"/api/users/{fake_user_id}",
            json={"role": "analyst"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_cannot_update_sso_user_role(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Cannot update role for SSO user (no password_hash)."""
        # Create an SSO user (no password_hash)
        sso_user = User(
            id=uuid.uuid4(),
            email="ssouser@example.com",
            password_hash=None,  # SSO users have no password
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(sso_user)
        await test_session.commit()

        response = await authenticated_client.patch(
            f"/api/users/{sso_user.id}",
            json={"role": "analyst"},
        )
        assert response.status_code == 400
        assert "sso" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_can_update_sso_user_is_active(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Can update is_active for SSO user."""
        # Create an SSO user
        sso_user = User(
            id=uuid.uuid4(),
            email="ssouser2@example.com",
            password_hash=None,
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(sso_user)
        await test_session.commit()

        response = await authenticated_client.patch(
            f"/api/users/{sso_user.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_user_invalid_role(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Update user with invalid role returns 400."""
        user = User(
            id=uuid.uuid4(),
            email="invalidroleuser@example.com",
            password_hash=get_password_hash("password123"),
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()

        response = await authenticated_client.patch(
            f"/api/users/{user.id}",
            json={"role": "invalid_role"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_update_user_requires_admin(
        self, client: AsyncClient
    ):
        """Update user endpoint requires admin authentication."""
        fake_user_id = uuid.uuid4()
        response = await client.patch(
            f"/api/users/{fake_user_id}",
            json={"role": "analyst"},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403


class TestResetPassword:
    """Tests for POST /users/{user_id}/reset-password endpoint."""

    @pytest.mark.asyncio
    async def test_reset_password_for_local_user(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Reset password for local user succeeds."""
        user = User(
            id=uuid.uuid4(),
            email="resetuser@example.com",
            password_hash=get_password_hash("oldpassword"),
            role=UserRole.ANALYST,
            is_active=True,
            must_change_password=False,
        )
        test_session.add(user)
        await test_session.commit()

        response = await authenticated_client.post(
            f"/api/users/{user.id}/reset-password",
        )
        assert response.status_code == 200
        data = response.json()
        assert "temporary_password" in data
        assert len(data["temporary_password"]) >= 12

    @pytest.mark.asyncio
    async def test_reset_password_sets_must_change_password(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Reset password sets must_change_password flag."""
        user = User(
            id=uuid.uuid4(),
            email="mustchangeuser@example.com",
            password_hash=get_password_hash("oldpassword"),
            role=UserRole.ANALYST,
            is_active=True,
            must_change_password=False,
        )
        test_session.add(user)
        await test_session.commit()

        response = await authenticated_client.post(
            f"/api/users/{user.id}/reset-password",
        )
        assert response.status_code == 200

        # Verify the flag was set by refreshing from DB
        await test_session.refresh(user)
        assert user.must_change_password is True

    @pytest.mark.asyncio
    async def test_cannot_reset_password_for_sso_user(
        self, authenticated_client: AsyncClient, test_session: AsyncSession
    ):
        """Cannot reset password for SSO user."""
        sso_user = User(
            id=uuid.uuid4(),
            email="ssoresetuser@example.com",
            password_hash=None,  # SSO users have no password
            role=UserRole.ANALYST,
            is_active=True,
        )
        test_session.add(sso_user)
        await test_session.commit()

        response = await authenticated_client.post(
            f"/api/users/{sso_user.id}/reset-password",
        )
        assert response.status_code == 400
        assert "sso" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_reset_password_nonexistent_user_returns_404(
        self, authenticated_client: AsyncClient
    ):
        """Reset password for non-existent user returns 404."""
        fake_user_id = uuid.uuid4()
        response = await authenticated_client.post(
            f"/api/users/{fake_user_id}/reset-password",
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_reset_password_requires_admin(
        self, client: AsyncClient
    ):
        """Reset password endpoint requires admin authentication."""
        fake_user_id = uuid.uuid4()
        response = await client.post(
            f"/api/users/{fake_user_id}/reset-password",
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403
