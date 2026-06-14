"""Unit tests for the audit hash-chain core (pure logic, no DB)."""

import hashlib
import hmac

from app.core.audit_chain import (
    GENESIS,
    audit_hmac_key,
    build_payload,
    canonicalize,
    compute_hash,
    verify_chain,
)


class TestCanonicalize:
    def test_deterministic_key_order(self):
        """Same dict with different insertion order -> identical canonical string."""
        a = {"b": 1, "a": 2, "c": 3}
        b = {"c": 3, "a": 2, "b": 1}
        assert canonicalize(a) == canonicalize(b)

    def test_sorts_keys_at_every_level(self):
        """Nested dicts are sorted recursively, not just the top level."""
        a = {"outer": {"z": 1, "a": {"y": 2, "x": 3}}}
        b = {"outer": {"a": {"x": 3, "y": 2}, "z": 1}}
        assert canonicalize(a) == canonicalize(b)

    def test_list_order_preserved(self):
        """List element order is meaningful and preserved."""
        assert canonicalize({"k": [1, 2, 3]}) != canonicalize({"k": [3, 2, 1]})

    def test_dates_iso_serialized(self):
        from datetime import UTC, datetime

        dt = datetime(2026, 6, 14, 10, 0, 0, tzinfo=UTC)
        out = canonicalize({"created_at": dt})
        assert "2026-06-14T10:00:00+00:00" in out

    def test_jsonb_roundtrip_byte_identical(self):
        """A payload re-read from JSONB (str keys, ISO date strings) canonicalizes
        byte-identically to the in-memory version (SPEC D5)."""
        from datetime import UTC, datetime

        dt = datetime(2026, 6, 14, 10, 0, 0, tzinfo=UTC)
        in_memory = {
            "action": "rule.create",
            "details": {"title": "T", "nested": {"b": 2, "a": 1}},
            "created_at": dt,
        }
        # Simulate JSONB round-trip: dates become ISO strings, dict survives.
        from_jsonb = {
            "action": "rule.create",
            "details": {"nested": {"a": 1, "b": 2}, "title": "T"},
            "created_at": dt.isoformat(),
        }
        assert canonicalize(in_memory) == canonicalize(from_jsonb)

    def test_decimal_normalizes_via_build_payload(self):
        """A Decimal in details hashes the same on write and on JSONB read-back.

        build_payload runs the projection through json dumps/loads (default=str),
        so a Decimal collapses to the string JSONB stores -> no false-positive tamper.
        """
        from decimal import Decimal

        write_side = build_payload({"action": "a", "details": {"amount": Decimal("1.50")}})
        # JSONB stores numbers/strings; a Decimal serialized with default=str becomes
        # the string "1.50", which is exactly what reads back.
        read_side = build_payload({"action": "a", "details": {"amount": "1.50"}})
        assert canonicalize(write_side) == canonicalize(read_side)


class TestComputeHash:
    def test_genesis_value(self):
        assert GENESIS == hashlib.sha256(b"chad:audit-genesis").hexdigest()

    def test_compute_hash_is_keyed_hmac_with_framing(self):
        prev = GENESIS
        canonical = canonicalize({"action": "x"})
        key = audit_hmac_key()
        message = bytes.fromhex(prev) + b"\x1f" + canonical.encode("utf-8")
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        assert compute_hash(prev, canonical) == expected

    def test_compute_hash_requires_64_hex_prev(self):
        import pytest

        with pytest.raises(ValueError):
            compute_hash("deadbeef", canonicalize({"a": 1}))

    def test_hash_changes_with_prev(self):
        canonical = canonicalize({"action": "x"})
        other_prev = hashlib.sha256(b"other").hexdigest()
        assert compute_hash(GENESIS, canonical) != compute_hash(other_prev, canonical)

    def test_hash_changes_with_payload(self):
        assert compute_hash(GENESIS, canonicalize({"a": 1})) != compute_hash(
            GENESIS, canonicalize({"a": 2})
        )

    def test_hash_changes_with_key(self):
        """A different HMAC key yields a different hash -> DB-only attacker can't forge."""
        canonical = canonicalize({"action": "x"})
        h1 = compute_hash(GENESIS, canonical, key=b"key-one-aaaaaaaaaaaaaaaaaaaaaaaa")
        h2 = compute_hash(GENESIS, canonical, key=b"key-two-bbbbbbbbbbbbbbbbbbbbbbbb")
        assert h1 != h2

    def test_wrong_key_fails_verification(self):
        """A chain signed with one key does not verify under another key."""
        key_a = b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        key_b = b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        canonical = canonicalize(build_payload({"action": "a1", "resource_type": "rule"}))
        row = {
            "action": "a1",
            "resource_type": "rule",
            "prev_hash": GENESIS,
            "hash": compute_hash(GENESIS, canonical, key=key_a),
        }
        assert verify_chain([row], key=key_a) is True
        assert verify_chain([row], key=key_b) is False


def _link(prev_hash: str, payload: dict) -> dict:
    """Build a valid chain row from a payload + prev_hash."""
    canonical = canonicalize(build_payload(payload))
    row = dict(payload)
    row["prev_hash"] = prev_hash
    row["hash"] = compute_hash(prev_hash, canonical)
    return row


class TestVerifyChain:
    def _good_chain(self) -> list[dict]:
        r1 = _link(GENESIS, {"action": "a1", "resource_type": "rule"})
        r2 = _link(r1["hash"], {"action": "a2", "resource_type": "user"})
        r3 = _link(r2["hash"], {"action": "a3", "resource_type": "rule"})
        return [r1, r2, r3]

    def test_valid_chain_passes(self):
        assert verify_chain(self._good_chain()) is True

    def test_empty_chain_passes(self):
        assert verify_chain([]) is True

    def test_mutated_row_detected(self):
        chain = self._good_chain()
        # Tamper with a payload field but keep the stored hash -> hash mismatch.
        chain[1]["action"] = "TAMPERED"
        assert verify_chain(chain) is False

    def test_deleted_link_detected(self):
        chain = self._good_chain()
        # Remove the middle row -> row3.prev_hash no longer matches row1.hash.
        broken = [chain[0], chain[2]]
        assert verify_chain(broken) is False

    def test_null_hash_row_fails(self):
        chain = self._good_chain()
        chain[1]["hash"] = None
        assert verify_chain(chain) is False
