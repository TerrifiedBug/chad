"""Decode VectorFlow (Auth.js v5) session cookies for delegated suite auth.

VectorFlow issues its session as an Auth.js v5 JWE (alg=dir,
enc=A256CBC-HS512) whose 64-byte content-encryption key is derived with
HKDF-SHA256 from the shared NEXTAUTH_SECRET, salted with the cookie name.
When CHAD_DELEGATED_AUTH is enabled, CHAD decodes that cookie directly so the
suite shares one login. Auth.js may split large cookies into chunks named
'<name>.0', '<name>.1', ... which must be concatenated before decryption.
"""

import binascii
import json
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jose import jwe
from jose.exceptions import JWEError

# Checked in order; the __Secure- name is what Auth.js sets over HTTPS.
SESSION_COOKIE_NAMES = ("__Secure-authjs.session-token", "authjs.session-token")

# Coupled to VectorFlow's suite_role contract (suite-role.ts). A new VF role requires
# updating this tuple in lockstep — decoder rejects unknown roles as VfSessionInvalid.
_SUITE_ROLES = ("admin", "editor", "viewer")


@dataclass
class VfSessionClaims:
    user_id: str
    email: str
    name: str | None
    suite_role: str
    org_id: str
    provider: str
    authed_at: int
    exp: int


class VfSessionError(Exception):
    """Base error for VectorFlow session decoding."""


class VfSessionInvalid(VfSessionError):
    """Session cookie present but undecryptable, malformed, or not authorized."""


class VfSessionExpired(VfSessionError):
    """Session decrypted fine but the token's exp is in the past."""


def derive_encryption_key(secret: str, cookie_name: str) -> bytes:
    """HKDF-SHA256 key derivation matching Auth.js v5 (jose deriveEncryptionKey)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=cookie_name.encode(),
        info=f"Auth.js Generated Encryption Key ({cookie_name})".encode(),
    ).derive(secret.encode())


def _read_cookie_value(cookies: dict[str, str], name: str) -> str | None:
    """Return the cookie value, reassembling chunked cookies '<name>.0', '<name>.1', ..."""
    if name in cookies:
        return cookies[name]
    chunks: list[str] = []
    index = 0
    while f"{name}.{index}" in cookies:
        chunks.append(cookies[f"{name}.{index}"])
        index += 1
    if chunks:
        return "".join(chunks)
    return None


def decode_vf_session(cookies: dict[str, str], secret: str) -> VfSessionClaims | None:
    """Decode a VectorFlow session from request cookies.

    Returns None when no session cookie is present (caller falls through to
    CHAD's own auth). Raises VfSessionExpired when the token's exp has passed
    and VfSessionInvalid for any other failure (bad ciphertext, malformed
    payload, missing claims, non-default org, unknown suite_role).
    """
    token: str | None = None
    cookie_name = ""
    for name in SESSION_COOKIE_NAMES:
        value = _read_cookie_value(cookies, name)
        if value:
            token, cookie_name = value, name
            break
    if token is None:
        return None

    key = derive_encryption_key(secret, cookie_name)
    try:
        plaintext = jwe.decrypt(token, key)
    except (JWEError, binascii.Error, ValueError) as exc:
        raise VfSessionInvalid(f"VF session JWE decryption failed: {exc}") from exc
    if plaintext is None:
        raise VfSessionInvalid("VF session JWE decryption produced no payload")

    try:
        payload = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VfSessionInvalid(f"VF session payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise VfSessionInvalid("VF session payload is not a JSON object")

    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise VfSessionInvalid("VF session payload missing integer 'exp' claim")
    if exp <= int(time.time()):
        raise VfSessionExpired(f"VF session expired at {exp}")

    org_id = payload.get("org_id")
    if org_id != "default":
        raise VfSessionInvalid(f"VF session org_id {org_id!r} is not 'default'")

    suite_role = payload.get("suite_role")
    if suite_role is None:
        # Pre-rollout sessions (minted before VF stamped suite_role) have no
        # suite_role key. They're otherwise legitimate, so fail open to LEAST
        # privilege rather than lock the user out. A PRESENT-but-unrecognized
        # value still raises — only an absent claim defaults.
        suite_role = "viewer"
    elif suite_role not in _SUITE_ROLES:
        raise VfSessionInvalid(f"VF session suite_role {suite_role!r} not in {_SUITE_ROLES}")

    user_id = payload.get("id")
    email = payload.get("email")
    provider = payload.get("provider")
    authed_at = payload.get("authedAt")
    if (
        not isinstance(user_id, str)
        or not isinstance(email, str)
        or not isinstance(provider, str)
        or not isinstance(authed_at, int)
    ):
        raise VfSessionInvalid("VF session payload missing required claims (id, email, provider, authedAt)")

    name_claim = payload.get("name")

    return VfSessionClaims(
        user_id=user_id,
        email=email,
        name=name_claim if isinstance(name_claim, str) else None,
        suite_role=suite_role,
        org_id=org_id,
        provider=provider,
        authed_at=authed_at,
        exp=exp,
    )
