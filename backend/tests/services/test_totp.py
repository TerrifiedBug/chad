"""Tests for TOTP service."""

import pyotp

from app.services.totp import (
    generate_backup_codes,
    generate_qr_uri,
    generate_totp_secret,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)


def test_generate_totp_secret():
    """Test TOTP secret generation."""
    secret = generate_totp_secret()
    assert len(secret) == 32
    # Should be base32 encoded
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)


def test_generate_qr_uri():
    """Test QR code URI generation."""
    secret = "JBSWY3DPEHPK3PXP"
    uri = generate_qr_uri(secret, "user@example.com", "CHAD")
    assert uri.startswith("otpauth://totp/")
    assert "CHAD" in uri
    assert "user%40example.com" in uri or "user@example.com" in uri
    assert secret in uri


def test_verify_totp_code_valid():
    """Test TOTP verification with valid code."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    code = totp.now()

    assert verify_totp_code(secret, code) is True


def test_verify_totp_code_invalid():
    """Test TOTP verification with invalid code."""
    secret = pyotp.random_base32()

    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "invalid") is False


def test_generate_backup_codes():
    """Test backup code generation."""
    codes = generate_backup_codes(10)
    assert len(codes) == 10
    # Each code should be 8 characters
    assert all(len(code) == 8 for code in codes)
    # All codes should be unique
    assert len(set(codes)) == 10


def test_hash_and_verify_backup_code():
    """Test backup code hashing and verification."""
    code = "ABCD1234"
    hashed = hash_backup_code(code)

    assert hashed != code
    assert verify_backup_code(code, hashed) is True
    assert verify_backup_code("WRONG123", hashed) is False
