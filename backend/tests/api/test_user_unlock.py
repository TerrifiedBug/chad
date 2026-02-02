import pytest

from app.services.rate_limit import is_account_locked, record_failed_attempt


@pytest.mark.asyncio
async def test_get_lock_status_unlocked(
    client,
    admin_user,
    admin_token
):
    """Test getting lock status for unlocked user."""
    response = await client.get(
        f"/api/users/lock-status/{admin_user.email}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["locked"] is False


@pytest.mark.asyncio
async def test_get_lock_status_locked(
    client,
    test_user,
    test_session,
    admin_token
):
    """Test getting lock status for locked user."""
    # Lock the account by recording failed attempts
    for _ in range(5):
        await record_failed_attempt(test_session, test_user.email, "127.0.0.1")

    response = await client.get(
        f"/api/users/lock-status/{test_user.email}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["locked"] is True
    assert response.json()["remaining_minutes"] is not None


@pytest.mark.asyncio
async def test_unlock_user(
    client,
    test_user,
    test_session,
    admin_token
):
    """Test unlocking a locked user."""
    # Lock the account by recording failed attempts
    for _ in range(5):
        await record_failed_attempt(test_session, test_user.email, "127.0.0.1")

    # Verify locked
    locked, _ = await is_account_locked(test_session, test_user.email)
    assert locked is True

    # Unlock
    response = await client.post(
        f"/api/users/{test_user.id}/unlock",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        }
    )
    assert response.status_code == 200
    assert response.json()["success"] is True

    # Verify unlocked
    locked, _ = await is_account_locked(test_session, test_user.email)
    assert locked is False
