#!/usr/bin/env python3
"""
Portable verifier for an exported CHAD audit hash-chain envelope.

Reads the envelope produced by ``GET /audit/export/chain`` (path arg or stdin),
re-derives the chain, and reports whether it is intact.

The keyed HMAC means verification needs the server secret: set ``CHAD_AUDIT_HMAC_KEY``
(or ``CHAD_ENCRYPTION_KEY`` to derive it, matching the running app). Without a key
the verifier cannot confirm anything and exits non-zero rather than silently passing.

Usage:
    CHAD_AUDIT_HMAC_KEY=... python scripts/verify_audit_chain.py envelope.json
    cat envelope.json | CHAD_ENCRYPTION_KEY=... python scripts/verify_audit_chain.py

Exit codes:
    0  chain verified (or empty)
    1  broken link / invalid envelope / missing key
"""
import hmac
import json
import os
import sys
from pathlib import Path

# Allow running as a standalone script (resolve the app package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.audit_chain import (  # noqa: E402
    GENESIS,
    audit_hmac_key,
    build_payload,
    canonicalize,
    compute_hash,
)


def _load(argv: list[str]) -> dict:
    if len(argv) > 1:
        raw = Path(argv[1]).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    return json.loads(raw)


def verify_envelope(envelope: dict, key: bytes) -> tuple[bool, str]:
    """Return (ok, message). On failure, message identifies the first broken link."""
    rows = envelope.get("rows", [])
    expected_prev = GENESIS
    for index, row in enumerate(rows):
        prev_hash = row.get("prev_hash")
        row_hash = row.get("hash")
        if prev_hash is None or row_hash is None:
            return False, f"row {index}: missing prev_hash/hash"
        if prev_hash != expected_prev:
            return False, (
                f"row {index} (hash={row_hash}): prev_hash does not match the "
                f"previous row's hash (expected {expected_prev})"
            )
        canonical = canonicalize(build_payload(row))
        recomputed = compute_hash(prev_hash, canonical, key)
        if not hmac.compare_digest(row_hash, recomputed):
            return False, (
                f"row {index} (hash={row_hash}): payload hash mismatch - row was "
                f"mutated or signed with a different key (recomputed {recomputed})"
            )
        expected_prev = row_hash
    return True, f"OK: {len(rows)} row(s) verified"


def main(argv: list[str]) -> int:
    # The HMAC key MUST be available; without it we cannot verify anything and must
    # not silently pass. A dedicated key or the encryption secret must be present.
    if not os.environ.get("CHAD_AUDIT_HMAC_KEY") and not os.environ.get("CHAD_ENCRYPTION_KEY"):
        print(
            "CANNOT VERIFY: no HMAC key available. Set CHAD_AUDIT_HMAC_KEY (or "
            "CHAD_ENCRYPTION_KEY to derive it) to the value used by the running app.",
            file=sys.stderr,
        )
        return 1

    try:
        envelope = _load(argv)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAILED to read envelope: {exc}", file=sys.stderr)
        return 1
    if not isinstance(envelope, dict) or not isinstance(envelope.get("rows", []), list):
        print("FAILED to read envelope: expected an object with a 'rows' list", file=sys.stderr)
        return 1

    key = audit_hmac_key()
    ok, message = verify_envelope(envelope, key)
    if ok:
        print(message)
        return 0
    print(f"BROKEN: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
