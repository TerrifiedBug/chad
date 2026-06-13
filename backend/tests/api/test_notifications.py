"""Tests for the notifications settings API endpoints."""

import uuid
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.notification_settings import NotificationSettings
from app.models.user import UserRole


class TestWebhookSendSSRF:
    """The alert webhook sender must block SSRF targets at egress."""

    @pytest.mark.asyncio
    async def test_send_to_webhook_blocks_internal_ip(self, monkeypatch):
        """A webhook URL resolving to an internal IP is blocked before any request."""
        import app.core.config as config_module
        from app.services.notification import _send_to_webhook

        # The dev/test container enables ALLOW_INTERNAL_WEBHOOK_IPS; force the
        # production posture so the SSRF guard actually engages.
        monkeypatch.setattr(config_module.settings, "ALLOW_INTERNAL_WEBHOOK_IPS", False)

        webhook = SimpleNamespace(
            id=uuid.uuid4(),
            url="http://169.254.169.254/latest/meta-data/",
            header_value=None,
            header_name=None,
            provider="generic",
        )

        success, error = await _send_to_webhook(webhook, {"type": "alert"})

        assert success is False
        assert "SSRF" in (error or "")

    @pytest.mark.asyncio
    async def test_send_to_webhook_blocks_non_http_scheme(self, monkeypatch):
        """Non-http(s) schemes are blocked regardless of the internal-IP setting."""
        import app.core.config as config_module
        from app.services.notification import _send_to_webhook

        monkeypatch.setattr(config_module.settings, "ALLOW_INTERNAL_WEBHOOK_IPS", True)

        webhook = SimpleNamespace(
            id=uuid.uuid4(),
            url="file:///etc/passwd",
            header_value=None,
            header_name=None,
            provider="generic",
        )

        success, error = await _send_to_webhook(webhook, {"type": "alert"})

        assert success is False
        assert "SSRF" in (error or "")


class TestMandatoryCommentsSettings:
    """Tests for mandatory comments settings management."""

    @pytest.mark.asyncio
    async def test_get_settings_returns_defaults_when_none_exist(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that GET returns defaults when no settings exist."""
        response = await authenticated_client.get("/api/notifications/settings")
        assert response.status_code == 200
        data = response.json()
        assert data["mandatory_rule_comments"] is True  # Default
        assert data["mandatory_comments_deployed_only"] is False  # Default

    @pytest.mark.asyncio
    async def test_get_settings_returns_existing_settings(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that GET returns existing settings."""
        # Create custom settings
        settings = NotificationSettings(
            mandatory_rule_comments=False,
            mandatory_comments_deployed_only=True,
        )
        test_session.add(settings)
        await test_session.commit()

        response = await authenticated_client.get("/api/notifications/settings")
        assert response.status_code == 200
        data = response.json()
        assert data["mandatory_rule_comments"] is False
        assert data["mandatory_comments_deployed_only"] is True

    @pytest.mark.asyncio
    async def test_update_settings_creates_new_settings(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that PUT creates settings when none exist."""
        response = await authenticated_client.put(
            "/api/notifications/settings",
            json={
                "mandatory_rule_comments": False,
                "mandatory_comments_deployed_only": True,
            },
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Settings updated successfully"

        # Verify settings were created
        result = await test_session.execute(select(NotificationSettings).limit(1))
        settings = result.scalar_one_or_none()
        assert settings is not None
        assert settings.mandatory_rule_comments is False
        assert settings.mandatory_comments_deployed_only is True

    @pytest.mark.asyncio
    async def test_update_settings_modifies_existing_settings(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that PUT modifies existing settings."""
        # Create initial settings
        settings = NotificationSettings(
            mandatory_rule_comments=True,
            mandatory_comments_deployed_only=False,
        )
        test_session.add(settings)
        await test_session.commit()

        # Update settings
        response = await authenticated_client.put(
            "/api/notifications/settings",
            json={
                "mandatory_rule_comments": False,
                "mandatory_comments_deployed_only": True,
            },
        )
        assert response.status_code == 200

        # Verify settings were updated
        await test_session.refresh(settings)
        assert settings.mandatory_rule_comments is False
        assert settings.mandatory_comments_deployed_only is True

    @pytest.mark.asyncio
    async def test_get_settings_requires_admin(self, client: AsyncClient, test_token, test_session):
        """Test that GET requires admin access."""
        import uuid

        from app.models.user import User

        # Create non-admin user
        user = User(
            id=uuid.uuid4(),
            email="user@example.com",
            password_hash="hash",
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token
        token = create_access_token(data={"sub": str(user.id)})

        response = await client.get(
            "/api/notifications/settings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_settings_requires_admin(self, client: AsyncClient, test_session):
        """Test that PUT requires admin access."""
        import uuid

        from app.models.user import User

        # Create non-admin user
        user = User(
            id=uuid.uuid4(),
            email="user@example.com",
            password_hash="hash",
            role=UserRole.VIEWER,
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()

        from app.core.security import create_access_token
        token = create_access_token(data={"sub": str(user.id)})

        response = await client.put(
            "/api/notifications/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "mandatory_rule_comments": False,
                "mandatory_comments_deployed_only": True,
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_settings_creates_audit_log(
        self, authenticated_client: AsyncClient, test_session, test_user
    ):
        """Test that updating settings creates an audit log entry."""
        from sqlalchemy import select

        from app.models.audit_log import AuditLog

        response = await authenticated_client.put(
            "/api/notifications/settings",
            json={
                "mandatory_rule_comments": True,
                "mandatory_comments_deployed_only": False,
            },
        )
        assert response.status_code == 200

        # Verify audit log was created
        result = await test_session.execute(
            select(AuditLog).where(AuditLog.action == "notification.settings.update")
        )
        audit_log = result.scalar_one_or_none()
        assert audit_log is not None
        assert audit_log.user_id == test_user.id
        assert audit_log.resource_type == "notification_setting"
        assert audit_log.resource_id == "mandatory_comments"
