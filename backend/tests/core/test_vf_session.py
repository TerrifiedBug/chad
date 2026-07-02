"""Tests for the VectorFlow (Auth.js v5) session cookie decoder.

Unit tests only — no DB (tests/core is exempted from DB setup in the root
conftest). The contract fixture is minted by VectorFlow's
scripts/mint-test-session.mjs so this suite proves both sides agree on the
HKDF derivation and JWE format.
"""

import json
import time
from pathlib import Path

import pytest
from jose import jwe

from app.core.vf_session import (
    VfSessionExpired,
    VfSessionInvalid,
    decode_vf_session,
    derive_encryption_key,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "vf-session-fixture.json"

SECRET = "unit-test-vf-session-secret-32-chars!!"
COOKIE = "authjs.session-token"
SECURE_COOKIE = "__Secure-authjs.session-token"


def _payload(**overrides) -> dict:
    """A valid VF session JWT payload; override individual claims per test."""
    base = {
        "id": "usr_123",
        "email": "danny@example.com",
        "name": "Danny",
        "suite_role": "editor",
        "org_id": "default",
        "provider": "credentials",
        "authedAt": int(time.time()) - 60,
        "exp": int(time.time()) + 3600,
    }
    base.update(overrides)
    return base


def _mint(payload: dict, cookie_name: str = COOKIE, secret: str = SECRET) -> str:
    """Mint a JWE exactly like Auth.js v5 does: dir / A256CBC-HS512 with an
    HKDF-SHA256 key (ikm=secret, salt=cookie_name,
    info='Auth.js Generated Encryption Key (<cookie_name>)', length=64)."""
    key = derive_encryption_key(secret, cookie_name)
    token = jwe.encrypt(
        json.dumps(payload).encode(),
        key,
        algorithm="dir",
        encryption="A256CBC-HS512",
    )
    return token.decode()


class TestDecodeVfSession:
    def test_returns_none_when_no_session_cookie(self):
        assert decode_vf_session({}, SECRET) is None
        assert decode_vf_session({"unrelated": "cookie"}, SECRET) is None

    def test_decodes_valid_plain_cookie(self):
        payload = _payload()
        claims = decode_vf_session({COOKIE: _mint(payload)}, SECRET)
        assert claims is not None
        assert claims.user_id == "usr_123"
        assert claims.email == "danny@example.com"
        assert claims.name == "Danny"
        assert claims.suite_role == "editor"
        assert claims.org_id == "default"
        assert claims.provider == "credentials"
        assert claims.authed_at == payload["authedAt"]
        assert claims.exp == payload["exp"]

    def test_decodes_secure_prefixed_cookie(self):
        """__Secure-authjs.session-token derives a DIFFERENT key (salt=cookie name)."""
        token = _mint(_payload(), cookie_name=SECURE_COOKIE)
        claims = decode_vf_session({SECURE_COOKIE: token}, SECRET)
        assert claims is not None
        assert claims.user_id == "usr_123"

    def test_chunked_cookie_concatenation(self):
        """Auth.js splits large cookies into <name>.0, <name>.1 — decoder must reassemble."""
        token = _mint(_payload())
        split = len(token) // 2
        cookies = {f"{COOKIE}.0": token[:split], f"{COOKIE}.1": token[split:]}
        claims = decode_vf_session(cookies, SECRET)
        assert claims is not None
        assert claims.email == "danny@example.com"

    def test_expired_token_raises_vf_session_expired(self):
        token = _mint(_payload(exp=int(time.time()) - 3600))
        with pytest.raises(VfSessionExpired):
            decode_vf_session({COOKIE: token}, SECRET)

    def test_non_default_org_raises_vf_session_invalid(self):
        token = _mint(_payload(org_id="acme"))
        with pytest.raises(VfSessionInvalid):
            decode_vf_session({COOKIE: token}, SECRET)

    def test_tampered_token_raises_vf_session_invalid(self):
        token = _mint(_payload())
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with pytest.raises(VfSessionInvalid):
            decode_vf_session({COOKIE: tampered}, SECRET)


class TestContractFixture:
    """Cross-repo contract: fixture minted by VF scripts/mint-test-session.mjs."""

    def test_fixture_roundtrip(self):
        fixture = json.loads(FIXTURE_PATH.read_text())
        claims = decode_vf_session(
            {fixture["cookie_name"]: fixture["cookie_value"]},
            fixture["secret"],
        )
        assert claims is not None
        for field_name, expected in fixture["expected_claims"].items():
            assert getattr(claims, field_name) == expected, field_name
