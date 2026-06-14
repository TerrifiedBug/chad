"""
Tamper-evidence hash chain for the audit log (single-tenant -> one global chain).

The chain is forward-only: each new audit row stores a keyed HMAC-SHA256 ``hash``
of its canonical payload linked to the previous row's hash via ``prev_hash``. A
portable verifier (``verify_chain`` / ``scripts/verify_audit_chain.py``) can
re-derive the chain from an exported envelope and detect any mutated, inserted,
deleted, or reordered row.

The HMAC is keyed by a server-held secret that is NOT stored in the database (see
``audit_hmac_key``), so an attacker with DB write access but no app secret cannot
forge a valid chain by recomputing hashes after editing rows.

Canonicalization is the load-bearing piece: a row written to JSONB and read back
must canonicalize byte-identically, otherwise the verifier would report a
false-positive tamper. We therefore (a) JSON-normalize the payload at write time
(via ``build_payload``) so non-JSON-native values like ``Decimal``/``set`` collapse
to exactly what JSONB stores, and (b) sort keys at *every* nesting level and emit
dates as ISO-8601 strings with stable separators.
"""
import hashlib
import hmac
import json
import os
from datetime import date, datetime
from typing import Any

# Fixed field set that defines a row's canonical payload. The chain hashes ONLY
# these fields, in this order; adding/removing a field changes every hash, so this
# set is intentionally frozen and documented (see SPEC-audit.md D2).
CANONICAL_FIELDS = (
    "action",
    "resource_type",
    "resource_id",
    "user_id",
    "details",
    "ip_address",
    "created_at",
)

# Genesis hash anchors the first link of the chain (prev_hash of the first row).
# This seed is unkeyed by design - it's a public constant, not a secret.
GENESIS = hashlib.sha256(b"chad:audit-genesis").hexdigest()

# Framing byte separating prev_hash from the canonical payload in the HMAC input,
# so no payload can ever collide with the prev_hash boundary.
_FRAME = b"\x1f"


def audit_hmac_key() -> bytes:
    """Resolve the server-held HMAC key for the audit chain.

    Priority:
      1. ``CHAD_AUDIT_HMAC_KEY`` env var (dedicated key, recommended in prod).
      2. Derived deterministically from ``CHAD_ENCRYPTION_KEY`` (the same app
         secret used by ``app/core/encryption.py``) so it is stable across
         restarts without being stored in any audit table.

    The key is never written to the database. Both the API and the standalone
    verifier CLI resolve it identically so an export can be re-verified offline by
    anyone holding the secret.
    """
    explicit = os.environ.get("CHAD_AUDIT_HMAC_KEY")
    if explicit:
        return explicit.encode("utf-8")
    # Fall back to deriving from the encryption secret. Default mirrors
    # encryption.get_encryption_key()'s dev default so local/dev stays consistent.
    base_secret = os.environ.get("CHAD_ENCRYPTION_KEY", "default-dev-key-change-in-prod")
    return hashlib.sha256(b"chad:audit-hmac:" + base_secret.encode("utf-8")).digest()


def _normalize(value: Any) -> Any:
    """Recursively normalize a value so it serializes deterministically.

    - dict: sort keys at every level (str-cast keys for a stable order).
    - list/tuple: normalize each element, preserving order (order is meaningful).
    - datetime/date: ISO-8601 string (round-trips a JSONB-stored ISO string).
    - everything else: returned as-is (json.dumps with sort_keys handles the rest).
    """
    if isinstance(value, dict):
        return {str(k): _normalize(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def canonicalize(payload: dict) -> str:
    """Serialize a row payload to a deterministic, stable JSON string.

    Keys are sorted at every nesting level and dates rendered as ISO-8601, so a
    payload built from in-memory objects and the same payload re-read from JSONB
    produce byte-identical output (SPEC-audit.md D5).
    """
    normalized = _normalize(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_hash(prev_hash: str, canonical: str, key: bytes | None = None) -> str:
    """Keyed HMAC-SHA256 hex of ``prev_hash`` framed with the canonical payload.

    Input is ``bytes.fromhex(prev_hash) + b"\\x1f" + canonical.encode()`` so the
    prev/payload boundary is unambiguous. ``prev_hash`` must be 64 hex chars
    (GENESIS and every produced hash are). ``key`` defaults to ``audit_hmac_key()``.
    """
    if len(prev_hash) != 64:
        raise ValueError(f"prev_hash must be 64 hex chars, got {len(prev_hash)}")
    if key is None:
        key = audit_hmac_key()
    message = bytes.fromhex(prev_hash) + _FRAME + canonical.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def build_payload(row: dict) -> dict:
    """Project an audit row (or dict) down to the fixed canonical field set.

    ``user_id`` is stringified (UUIDs round-trip as strings in JSON/JSONB). The
    whole projection is run through a JSON dumps/loads cycle (``default=str``) so
    non-JSON-native values written into ``details`` (e.g. ``Decimal``, ``float``,
    ``set``) collapse to exactly the representation JSONB will store and read back
    - otherwise write-time and read-back hashes would differ (false-positive
    tamper). ``created_at`` is left as a datetime for ``canonicalize`` to ISO-render.
    """
    payload: dict[str, Any] = {}
    created_at = row.get("created_at")
    for field in CANONICAL_FIELDS:
        value = row.get(field)
        if field == "user_id" and value is not None:
            value = str(value)
        payload[field] = value
    # Normalize through JSON to match the JSONB round-trip. created_at is excluded
    # from this pass (datetime isn't JSON-native and canonicalize ISO-renders it).
    payload.pop("created_at", None)
    payload = json.loads(json.dumps(payload, default=str))
    payload["created_at"] = created_at
    return payload


def verify_chain(rows: list[dict], key: bytes | None = None) -> bool:
    """Verify a list of audit rows forms an unbroken keyed hash chain.

    ``rows`` must be ordered prev_hash -> hash (the export topology). Each row must
    carry the canonical payload fields plus ``prev_hash`` and ``hash``. Returns
    True only if every link holds: ``row.prev_hash`` equals the previous row's
    ``hash`` (or GENESIS for the first row), and ``row.hash`` equals
    ``compute_hash(row.prev_hash, canonicalize(build_payload(row)), key)``.
    """
    if key is None:
        key = audit_hmac_key()
    expected_prev = GENESIS
    for row in rows:
        prev_hash = row.get("prev_hash")
        row_hash = row.get("hash")
        if prev_hash is None or row_hash is None:
            return False
        if prev_hash != expected_prev:
            return False
        canonical = canonicalize(build_payload(row))
        if not hmac.compare_digest(row_hash, compute_hash(prev_hash, canonical, key)):
            return False
        expected_prev = row_hash
    return True
