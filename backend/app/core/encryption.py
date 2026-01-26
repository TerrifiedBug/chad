import base64
import hashlib
import os

from cryptography.fernet import Fernet


def get_encryption_key() -> bytes:
    """Derive Fernet key from environment variable.

    In production, CHAD_ENCRYPTION_KEY must be set to a secure value.
    In development, defaults are allowed with a warning.
    """
    secret = os.environ.get("CHAD_ENCRYPTION_KEY", "default-dev-key-change-in-prod")

    if not secret or secret.strip() == "":
        raise ValueError(
            "CHAD_ENCRYPTION_KEY must be set in environment variables. "
            "Generate a secure random key using: openssl rand -base64 32"
        )

    # Check for known insecure default values
    insecure_defaults = [
        "default-dev-key-change-in-prod",
        "dev-secret-key-change-in-prod",
        "dev-session-key-change-in-prod",
        "secret",
        "changeme",
    ]

    if secret.lower() in insecure_defaults:
        # In development, allow insecure defaults with a warning
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            "CHAD_ENCRYPTION_KEY is using an insecure default value. "
            "This is acceptable for development but MUST be changed in production!"
        )
    # Minimum length check (only enforce if not using default)
    elif len(secret) < 32:
        raise ValueError(
            "CHAD_ENCRYPTION_KEY must be at least 32 characters long for security. "
            "Generate a secure key using: openssl rand -base64 32"
        )

    # Fernet requires 32 url-safe base64-encoded bytes
    key = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a string, return base64 encoded ciphertext."""
    f = Fernet(get_encryption_key())
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt base64 encoded ciphertext, return plaintext."""
    f = Fernet(get_encryption_key())
    return f.decrypt(ciphertext.encode()).decode()
