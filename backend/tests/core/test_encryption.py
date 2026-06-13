"""Tests for at-rest encryption helpers and the encrypted model properties."""

from app.core.encryption import decrypt, decrypt_with_fallback, encrypt
from app.models.index_pattern import IndexPattern
from app.models.user import User


class TestEncryptionHelpers:
    def test_encrypt_decrypt_round_trip(self):
        assert decrypt(encrypt("hunter2")) == "hunter2"

    def test_ciphertext_differs_from_plaintext(self):
        assert encrypt("hunter2") != "hunter2"

    def test_fallback_returns_plaintext_for_non_ciphertext(self):
        # Legacy/not-yet-migrated plaintext rows must pass through untouched.
        assert decrypt_with_fallback("legacy-plaintext-token") == "legacy-plaintext-token"

    def test_fallback_decrypts_ciphertext(self):
        assert decrypt_with_fallback(encrypt("secret")) == "secret"

    def test_fallback_handles_none_and_empty(self):
        assert decrypt_with_fallback(None) is None
        assert decrypt_with_fallback("") == ""


class TestIndexPatternAuthTokenEncryption:
    def test_auth_token_stored_encrypted_read_plaintext(self):
        ip = IndexPattern(name="n", pattern="p-*", percolator_index="chad-percolator-p")
        ip.auth_token = "shipper-token-123"
        # Column holds ciphertext, property returns plaintext.
        assert ip.auth_token_encrypted != "shipper-token-123"
        assert ip.auth_token == "shipper-token-123"

    def test_auth_token_kwarg_round_trips(self):
        ip = IndexPattern(
            name="n2", pattern="p2-*", percolator_index="chad-percolator-p2",
            auth_token="kwarg-token",
        )
        assert ip.auth_token == "kwarg-token"


class TestUserTotpSecretEncryption:
    def test_totp_secret_stored_encrypted_read_plaintext(self):
        u = User(email="u@example.com")
        u.totp_secret = "JBSWY3DPEHPK3PXP"
        assert u.totp_secret_encrypted != "JBSWY3DPEHPK3PXP"
        assert u.totp_secret == "JBSWY3DPEHPK3PXP"

    def test_totp_secret_none_stays_none(self):
        u = User(email="u2@example.com")
        u.totp_secret = None
        assert u.totp_secret_encrypted is None
        assert u.totp_secret is None
