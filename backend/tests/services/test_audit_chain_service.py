"""Service-level tests for audit_log() hash chaining (real Postgres, real lock)."""

import pytest
from sqlalchemy import select

from app.core.audit_chain import GENESIS, build_payload, canonicalize, compute_hash, verify_chain
from app.models.audit_chain_tail import AuditChainTail
from app.models.audit_log import AuditLog
from app.services.audit import audit_log


@pytest.mark.asyncio
async def test_first_write_links_to_genesis(test_session, test_user):
    log = await audit_log(
        test_session, test_user.id, "rule.create", "rule", "r1", {"title": "T"}
    )
    await test_session.commit()
    assert log.prev_hash == GENESIS
    assert log.hash is not None
    # Tail points at the new head.
    tail = await test_session.get(AuditChainTail, "global")
    assert tail.last_hash == log.hash


@pytest.mark.asyncio
async def test_two_sequential_writes_are_linked(test_session, test_user):
    """The advisory-lock path: row2.prev_hash == row1.hash."""
    log1 = await audit_log(test_session, test_user.id, "rule.create", "rule", "r1", {"a": 1})
    await test_session.commit()
    log2 = await audit_log(test_session, test_user.id, "rule.update", "rule", "r1", {"a": 2})
    await test_session.commit()

    assert log1.prev_hash == GENESIS
    assert log2.prev_hash == log1.hash
    tail = await test_session.get(AuditChainTail, "global")
    assert tail.last_hash == log2.hash


@pytest.mark.asyncio
async def test_jsonb_roundtrip_canonicalizes_identically(test_session, test_user):
    """A row read back from JSONB recomputes the same hash (no false-positive tamper)."""
    log = await audit_log(
        test_session,
        test_user.id,
        "rule.create",
        "rule",
        "r1",
        {"title": "T", "nested": {"z": 1, "a": {"y": 2, "x": 3}}, "list": [3, 1, 2]},
    )
    await test_session.commit()
    stored_hash = log.hash
    stored_prev = log.prev_hash

    # Re-read from the DB (forces a JSONB round-trip of details).
    test_session.expunge_all()
    row = (await test_session.execute(select(AuditLog).where(AuditLog.id == log.id))).scalar_one()

    canonical = canonicalize(
        build_payload(
            {
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "user_id": row.user_id,
                "details": row.details,
                "ip_address": row.ip_address,
                "created_at": row.created_at,
            }
        )
    )
    assert compute_hash(stored_prev, canonical) == stored_hash


@pytest.mark.asyncio
async def test_chain_of_writes_verifies(test_session, test_user):
    """A run of audit_log() writes forms a chain that verify_chain() accepts."""
    for i in range(5):
        await audit_log(
            test_session, test_user.id, f"action.{i}", "rule", f"r{i}", {"i": i, "ip": "x"}
        )
        await test_session.commit()

    rows = (
        await test_session.execute(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id))
    ).scalars().all()
    payloads = [
        {
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "user_id": r.user_id,
            "details": r.details,
            "ip_address": r.ip_address,
            "created_at": r.created_at,
            "prev_hash": r.prev_hash,
            "hash": r.hash,
        }
        for r in rows
    ]
    assert verify_chain(payloads) is True


@pytest.mark.asyncio
async def test_decimal_and_float_details_roundtrip_verifies(test_session, test_user):
    """A row whose details carries a Decimal + float still verifies after JSONB read-back.

    The write path normalizes details through json dumps/loads (default=str), so the
    stored JSONB matches the hashed payload - no false-positive tamper, and the
    engine never sees a non-serializable Decimal.
    """
    from decimal import Decimal

    log = await audit_log(
        test_session,
        test_user.id,
        "billing.charge",
        "invoice",
        "inv-1",
        {"amount": Decimal("19.99"), "rate": 0.175, "qty": 3},
    )
    await test_session.commit()
    stored_hash = log.hash

    # Re-read from the DB (forces the JSONB round-trip of details).
    test_session.expunge_all()
    rows = (
        await test_session.execute(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id))
    ).scalars().all()
    payloads = [
        {
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "user_id": r.user_id,
            "details": r.details,
            "ip_address": r.ip_address,
            "created_at": r.created_at,
            "prev_hash": r.prev_hash,
            "hash": r.hash,
        }
        for r in rows
    ]
    assert rows[-1].hash == stored_hash
    assert verify_chain(payloads) is True
