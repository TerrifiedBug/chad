"""
TOTP (Time-based One-Time Password) service.

Handles 2FA setup, verification, and backup code management.
"""

import secrets
import string

import pyotp
from passlib.context import CryptContext

# Use bcrypt for backup code hashing (same as passwords)
backup_code_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret.

    Returns:
        32-character base32 encoded secret
    """
    return pyotp.random_base32(length=32)


def generate_qr_uri(secret: str, email: str, issuer: str = "CHAD") -> str:
    """
    Generate an otpauth:// URI for QR code display.

    Args:
        secret: TOTP secret
        email: User's email address
        issuer: Application name

    Returns:
        otpauth:// URI string
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code.

    Args:
        secret: User's TOTP secret
        code: 6-digit code to verify

    Returns:
        True if code is valid, False otherwise
    """
    if not code or len(code) != 6 or not code.isdigit():
        return False

    totp = pyotp.TOTP(secret)
    # valid_window=1 allows for 30 seconds clock drift
    return totp.verify(code, valid_window=1)


def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Generate backup codes for 2FA recovery.

    Args:
        count: Number of codes to generate

    Returns:
        List of 8-character alphanumeric codes
    """
    alphabet = string.ascii_uppercase + string.digits
    codes = []
    for _ in range(count):
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        codes.append(code)
    return codes


def hash_backup_code(code: str) -> str:
    """
    Hash a backup code for storage.

    Args:
        code: Plain text backup code

    Returns:
        Hashed backup code
    """
    return backup_code_context.hash(code)


def verify_backup_code(code: str, hashed: str) -> bool:
    """
    Verify a backup code against its hash.

    Args:
        code: Plain text backup code
        hashed: Hashed backup code from database

    Returns:
        True if code matches, False otherwise
    """
    return backup_code_context.verify(code, hashed)
