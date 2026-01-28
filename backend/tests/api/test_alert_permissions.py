"""Tests for alert permissions integration."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text


@pytest.mark.asyncio
async def test_alert_delete_requires_manage_alerts(
    async_client: AsyncClient,
    test_session,
    admin_token: str
):
    """Test that deleting an alert requires manage_alerts permission."""
    # Create a test user with only manage_rules permission
    from app.models.user import User
    from app.core.security import get_password_hash

    user = User(
        username="test_user_rules_only",
        email="test_rules@example.com",
        hashed_password=get_password_hash("testpass"),
        role="analyst",
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
    from app.core.security import create_access_token
    token = create_access_token(user.username)

    # Create a test alert
    alert_id = uuid.uuid4()
    await test_session.execute(
        text("""
            INSERT INTO alerts (id, rule_id, status, data, created_at)
            VALUES (:id, :rule_id, 'new', '{}', now())
        """),
        {"id": str(alert_id), "rule_id": str(uuid.uuid4())}
    )
    await test_session.commit()

    # Try to delete alert with user who has only manage_rules
    response = await async_client.delete(
        f"/api/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    # Should fail because user doesn't have manage_alerts
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_alert_delete_with_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that deleting an alert works with manage_alerts permission."""
    from app.models.user import User
    from app.core.security import get_password_hash, create_access_token

    # Create a test user with only manage_alerts permission
    user = User(
        username="test_user_alerts_only",
        email="test_alerts@example.com",
        hashed_password=get_password_hash("testpass"),
        role="analyst",
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

    token = create_access_token(user.username)

    # Create a test alert
    alert_id = uuid.uuid4()
    await test_session.execute(
        text("""
            INSERT INTO alerts (id, rule_id, status, data, created_at)
            VALUES (:id, :rule_id, 'new', '{}', now())
        """),
        {"id": str(alert_id), "rule_id": str(uuid.uuid4())}
    )
    await test_session.commit()

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
    from app.models.user import User
    from app.core.security import get_password_hash, create_access_token

    # Create user without manage_alerts
    user = User(
        username="test_user_no_alerts",
        email="test_no_alerts@example.com",
        hashed_password=get_password_hash("testpass"),
        role="viewer",
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

    token = create_access_token(user.username)

    # Try bulk status update
    response = await async_client.patch(
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
    from app.models.user import User
    from app.core.security import get_password_hash, create_access_token

    # Create user without manage_alerts
    user = User(
        username="test_user_no_delete",
        email="test_no_delete@example.com",
        hashed_password=get_password_hash("testpass"),
        role="viewer",
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    token = create_access_token(user.username)

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
    # Check that admin role has both permissions
    result = await test_session.execute(
        text("""
            SELECT permission, granted
            FROM role_permissions
            WHERE role = 'admin'
            AND permission IN ('manage_rules', 'manage_alerts')
        """)
    )
    permissions = {row[0]: row[1] for row in result.fetchall()}

    assert permissions.get("manage_rules") is True
    assert permissions.get("manage_alerts") is True


@pytest.mark.asyncio
async def test_analyst_has_both_permissions_by_default(
    async_client: AsyncClient,
    test_session
):
    """Test that analyst role has both manage_rules and manage_alerts by default."""
    # Check that analyst role has both permissions
    result = await test_session.execute(
        text("""
            SELECT permission, granted
            FROM role_permissions
            WHERE role = 'analyst'
            AND permission IN ('manage_rules', 'manage_alerts')
        """)
    )
    permissions = {row[0]: row[1] for row in result.fetchall()}

    assert permissions.get("manage_rules") is True
    assert permissions.get("manage_alerts") is True


@pytest.mark.asyncio
async def test_viewer_has_no_management_permissions(
    async_client: AsyncClient,
    test_session
):
    """Test that viewer role has no management permissions."""
    # Check that viewer role has no management permissions
    result = await test_session.execute(
        text("""
            SELECT permission, granted
            FROM role_permissions
            WHERE role = 'viewer'
            AND permission IN ('manage_rules', 'manage_alerts')
        """)
    )
    permissions = {row[0]: row[1] for row in result.fetchall()}

    assert permissions.get("manage_rules") is False
    assert permissions.get("manage_alerts") is False


@pytest.mark.asyncio
async def test_alert_status_update_requires_manage_alerts(
    async_client: AsyncClient,
    test_session
):
    """Test that updating alert status requires manage_alerts permission."""
    from app.models.user import User
    from app.core.security import get_password_hash, create_access_token

    # Create user with only manage_rules
    user = User(
        username="test_user_rules_only_status",
        email="test_rules_status@example.com",
        hashed_password=get_password_hash("testpass"),
        role="analyst",
        is_active=True
    )
    test_session.add(user)
    await test_session.commit()

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

    token = create_access_token(user.username)

    # Create a test alert
    alert_id = uuid.uuid4()
    await test_session.execute(
        text("""
            INSERT INTO alerts (id, rule_id, status, data, created_at)
            VALUES (:id, :rule_id, 'new', '{}', now())
        """),
        {"id": str(alert_id), "rule_id": str(uuid.uuid4())}
    )
    await test_session.commit()

    # Try to update status
    response = await async_client.patch(
        f"/api/alerts/{alert_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "acknowledged"}
    )
    assert response.status_code == 403
