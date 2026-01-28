import pytest
from app.services.rate_limit import record_failed_attempt, is_account_locked



@pytest.mark.asyncio
async def test_get_lock_status_unlocked(
    client,
    admin_user
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
    db_session
):
    """Test getting lock status for locked user."""
    # Lock the account
    for _ in range(5):
        record_failed_attempt(db_session, test_user.email, "127.0.0.1")

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
    db_session
):
    """Test unlocking a locked user."""
    # Lock the account
    for _ in range(5):
        record_failed_attempt(db_session, test_user.email, "127.0.0.1")

    # Verify locked
    assert is_account_locked(db_session, test_user.email)[0] is True

    # Unlock
    response = await client.post(
        f"/api/users/{test_user.id}/unlock",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["success"] is True

    # Verify unlocked
    assert is_account_locked(db_session, test_user.email)[0] is False
