"""Tests for User 2FA fields."""

import pytest

from app.models.user import User


@pytest.mark.asyncio
async def test_user_2fa_fields_exist(test_session):
    """Test that 2FA fields exist on User model."""
    user = User(
        email="test@example.com",
        password_hash="hashed",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    assert user.totp_secret is None
    assert user.totp_enabled is False
    assert user.totp_backup_codes is None


@pytest.mark.asyncio
async def test_user_2fa_enabled(test_session):
    """Test user with 2FA enabled."""
    user = User(
        email="2fa@example.com",
        password_hash="hashed",
        totp_secret="JBSWY3DPEHPK3PXP",
        totp_enabled=True,
        totp_backup_codes=["code1hash", "code2hash"],
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    assert user.totp_secret == "JBSWY3DPEHPK3PXP"
    assert user.totp_enabled is True
    assert len(user.totp_backup_codes) == 2
