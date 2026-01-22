import base64
import hashlib
import os

from cryptography.fernet import Fernet


def get_encryption_key() -> bytes:
    """Derive Fernet key from environment variable."""
    secret = os.environ.get("CHAD_ENCRYPTION_KEY", "default-dev-key-change-in-prod")
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
