"""Tests for alert permissions integration."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text


def create_fake_alert_id() -> str:
    """Generate a fake alert ID for permission tests.

    These tests only verify permission checks (403 responses),
    so no real alert needs to exist.
    """
    return str(uuid.uuid4())


@pytest.mark.asyncio
async def test_alert_delete_requires_manage_alerts(
    async_client: AsyncClient,
    test_session,
    admin_token: str
):
    """Test that deleting an alert requires manage_alerts permission."""
    # Create a test user with only manage_rules permission
    from app.core.security import create_access_token, get_password_hash
    from app.models.user import User, UserRole

    user = User(
        email="test_rules@example.com",
        password_hash=get_password_hash("testpass"),
        role=UserRole.ANALYST,
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Grant only manage_rules permission (not manage_alerts)
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_rules', true)
            ON CONFLICT (role, permission) DO UPDATE SET granted = true
        """)
    )
    # Revoke manage_alerts for this test
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_alerts', false)
            ON CONFLICT (role, permission) DO UPDATE SET granted = false
        """)
    )
    await test_session.commit()

    # Create token for this user
    token = create_access_token(data={"sub": str(user.id)})

    # Create a test alert with all required dependencies
    alert_id = create_fake_alert_id()

    # Try to delete alert with user who has only manage_rules
    response = await async_client.delete(
        f"/api/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    # Should fail because user doesn't have manage_alerts
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()


@pytest.mark.asyncio
@pytest.mark.skip(reason="Requires OpenSearch to be running - permission check passes but actual delete needs OpenSearch")
async def test_alert_delete_with_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that deleting an alert works with manage_alerts permission."""
    from app.core.security import create_access_token, get_password_hash
    from app.models.user import User, UserRole

    # Create a test user with only manage_alerts permission
    user = User(
        email="test_alerts@example.com",
        password_hash=get_password_hash("testpass"),
        role=UserRole.ANALYST,
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Grant only manage_alerts permission (not manage_rules)
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_alerts', true)
            ON CONFLICT (role, permission) DO UPDATE SET granted = true
        """)
    )
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_rules', false)
            ON CONFLICT (role, permission) DO UPDATE SET granted = false
        """)
    )
    await test_session.commit()

    token = create_access_token(data={"sub": str(user.id)})

    # Create a test alert with all required dependencies
    alert_id = create_fake_alert_id()

    # Delete alert should succeed
    response = await async_client.delete(
        f"/api/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_bulk_status_update_requires_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that bulk status update requires manage_alerts permission."""
    from app.core.security import create_access_token, get_password_hash
    from app.models.user import User, UserRole

    # Create user without manage_alerts
    user = User(
        email="test_no_alerts@example.com",
        password_hash=get_password_hash("testpass"),
        role=UserRole.VIEWER,
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Revoke all permissions
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('viewer', 'manage_alerts', false)
            ON CONFLICT (role, permission) DO UPDATE SET granted = false
        """)
    )
    await test_session.commit()

    token = create_access_token(data={"sub": str(user.id)})

    # Try bulk status update (POST, not PATCH per the API definition)
    response = await async_client.post(
        "/api/alerts/bulk/status",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "alert_ids": [str(uuid.uuid4())],
            "status": "acknowledged"
        }
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_bulk_delete_requires_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that bulk delete requires manage_alerts permission."""
    from app.core.security import create_access_token, get_password_hash
    from app.models.user import User, UserRole

    # Create user without manage_alerts
    user = User(
        email="test_no_delete@example.com",
        password_hash=get_password_hash("testpass"),
        role=UserRole.VIEWER,
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    token = create_access_token(data={"sub": str(user.id)})

    # Try bulk delete
    response = await async_client.post(
        "/api/alerts/bulk/delete",
        headers={"Authorization": f"Bearer {token}"},
        json={"alert_ids": [str(uuid.uuid4())]}
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_has_both_permissions(
    async_client: AsyncClient,
    test_session,
    admin_token: str
):
    """Test that admin has both manage_rules and manage_alerts."""
    # Use the permission service to check permissions
    from app.services.permissions import get_role_permissions

    permissions = await get_role_permissions(test_session, "admin")

    assert permissions.get("manage_rules") is True
    assert permissions.get("manage_alerts") is True


@pytest.mark.asyncio
async def test_analyst_has_both_permissions_by_default(
    async_client: AsyncClient,
    test_session
):
    """Test that analyst role has both manage_rules and manage_alerts by default."""
    # Use the permission service to check permissions
    from app.services.permissions import get_role_permissions

    permissions = await get_role_permissions(test_session, "analyst")

    assert permissions.get("manage_rules") is True
    assert permissions.get("manage_alerts") is True


@pytest.mark.asyncio
async def test_viewer_has_no_management_permissions(
    async_client: AsyncClient,
    test_session
):
    """Test that viewer role has no management permissions."""
    # Use the permission service to check permissions
    from app.services.permissions import get_role_permissions

    permissions = await get_role_permissions(test_session, "viewer")

    assert permissions.get("manage_rules") is False
    assert permissions.get("manage_alerts") is False


@pytest.mark.asyncio
async def test_alert_status_update_requires_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that updating alert status requires manage_alerts permission."""
    from app.core.security import create_access_token, get_password_hash
    from app.models.user import User, UserRole

    # Create user with only manage_rules
    user = User(
        email="test_rules_status@example.com",
        password_hash=get_password_hash("testpass"),
        role=UserRole.ANALYST,
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Grant manage_rules, revoke manage_alerts
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_rules', true)
            ON CONFLICT (role, permission) DO UPDATE SET granted = true
        """)
    )
    await test_session.execute(
        text("""
            INSERT INTO role_permissions (role, permission, granted)
            VALUES ('analyst', 'manage_alerts', false)
            ON CONFLICT (role, permission) DO UPDATE SET granted = false
        """)
    )
    await test_session.commit()

    token = create_access_token(data={"sub": str(user.id)})

    # Create a test alert with all required dependencies
    alert_id = create_fake_alert_id()

    # Try to update status
    response = await async_client.patch(
        f"/api/alerts/{alert_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "acknowledged"}
    )
    assert response.status_code == 403
