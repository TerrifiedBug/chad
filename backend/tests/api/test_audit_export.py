"""Tests for audit export hardening (10k cap, CSV injection guard, chain envelope)."""

import csv
import io
import json
import os
import subprocess
import sys
import uuid

import pytest

from app.api.audit import EXPORT_ROW_CAP
from app.models.audit_log import AuditLog
from app.services.audit import audit_log

# The CLI verifier derives its HMAC key the same way the in-process app does. Both
# fall back to deriving from CHAD_ENCRYPTION_KEY (dev default when unset), but the
# CLI hard-requires one of the key env vars to be *present* so it never silently
# passes. Hand it the same dev-default value the app used so the keys match.
_VERIFIER_ENV = {
    **os.environ,
    "CHAD_ENCRYPTION_KEY": os.environ.get(
        "CHAD_ENCRYPTION_KEY", "default-dev-key-change-in-prod"
    ),
}


@pytest.mark.asyncio
async def test_export_caps_at_10k_with_truncated_header(
    authenticated_client, test_session, test_user
):
    """Insert >10k rows -> CSV export returns <=10k rows + truncated header."""
    # Bulk-insert raw rows (no chaining needed; export reads them directly).
    rows = [
        AuditLog(
            id=uuid.uuid4(),
            user_id=test_user.id,
            action="bulk.event",
            resource_type="rule",
            resource_id=str(i),
            details={"i": i},
        )
        for i in range(EXPORT_ROW_CAP + 50)
    ]
    test_session.add_all(rows)
    await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export?format=csv")
    assert resp.status_code == 200
    assert resp.headers.get("X-Audit-Export-Truncated") == "true"

    reader = list(csv.reader(io.StringIO(resp.text)))
    data_rows = reader[1:]  # drop header
    assert len(data_rows) == EXPORT_ROW_CAP


@pytest.mark.asyncio
async def test_export_not_truncated_under_cap(authenticated_client, test_session, test_user):
    rows = [
        AuditLog(
            id=uuid.uuid4(), user_id=test_user.id, action="a", resource_type="rule",
            resource_id=str(i), details=None,
        )
        for i in range(5)
    ]
    test_session.add_all(rows)
    await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export?format=csv")
    assert resp.status_code == 200
    assert "X-Audit-Export-Truncated" not in resp.headers


@pytest.mark.asyncio
async def test_json_export_capped(authenticated_client, test_session, test_user):
    rows = [
        AuditLog(
            id=uuid.uuid4(), user_id=test_user.id, action="a", resource_type="rule",
            resource_id=str(i), details=None,
        )
        for i in range(EXPORT_ROW_CAP + 10)
    ]
    test_session.add_all(rows)
    await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export?format=json")
    assert resp.status_code == 200
    assert resp.headers.get("X-Audit-Export-Truncated") == "true"
    data = json.loads(resp.text)
    assert len(data) == EXPORT_ROW_CAP


@pytest.mark.asyncio
async def test_csv_formula_injection_guard(authenticated_client, test_session, test_user):
    """A details value like '=cmd()' comes back prefixed with a single quote."""
    log = AuditLog(
        id=uuid.uuid4(),
        user_id=test_user.id,
        action="@evil",          # leading @ in a plain field
        resource_type="rule",
        resource_id="=danger",   # leading = in a plain field
        details={"payload": "=cmd()|calc"},
    )
    test_session.add(log)
    await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export?format=csv")
    assert resp.status_code == 200
    reader = list(csv.reader(io.StringIO(resp.text)))
    header, row = reader[0], reader[1]
    cells = dict(zip(header, row, strict=True))

    # Action (@evil) and Resource ID (=danger) must be quote-prefixed.
    assert cells["Action"] == "'@evil"
    assert cells["Resource ID"] == "'=danger"
    # The serialized details cell starts with {"... so is not itself dangerous,
    # but the embedded formula stays inert because the whole cell is one field.
    assert "=cmd()|calc" in cells["Details"]
    # The details JSON cell starts with '{' (safe) -> not prefixed.
    assert cells["Details"].startswith("{")


@pytest.mark.asyncio
async def test_chain_envelope_verifies_via_cli(authenticated_client, test_session, test_user):
    """The /audit/export/chain envelope passes the standalone verifier CLI."""
    for i in range(4):
        await audit_log(
            test_session, test_user.id, f"action.{i}", "rule", f"r{i}", {"i": i}
        )
        await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export/chain")
    assert resp.status_code == 200
    envelope = resp.json()
    assert envelope["verifier_version"] == 1
    assert "exported_at" in envelope
    assert len(envelope["rows"]) == 4

    # Run the portable verifier against the envelope via stdin.
    proc = subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"],
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
        cwd="/app",
        env=_VERIFIER_ENV,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "OK" in proc.stdout


@pytest.mark.asyncio
async def test_chain_envelope_excludes_legacy_null_hash_rows(
    authenticated_client, test_session, test_user
):
    """Legacy rows (no hash) are excluded from the verifiable envelope."""
    # A chained row.
    await audit_log(test_session, test_user.id, "chained.event", "rule", "r1", {"a": 1})
    await test_session.commit()
    # A legacy raw row with NULL hash (inserted directly, not via audit_log()).
    legacy = AuditLog(
        id=uuid.uuid4(), user_id=test_user.id, action="legacy", resource_type="rule",
        resource_id="old", details=None,
    )
    test_session.add(legacy)
    await test_session.commit()

    resp = await authenticated_client.get("/api/audit/export/chain")
    assert resp.status_code == 200
    actions = [r["action"] for r in resp.json()["rows"]]
    assert "chained.event" in actions
    assert "legacy" not in actions


@pytest.mark.asyncio
async def test_cli_detects_mutated_row(authenticated_client, test_session, test_user):
    """Tampering a row in the exported envelope makes the CLI exit non-zero."""
    for i in range(3):
        await audit_log(test_session, test_user.id, f"a{i}", "rule", str(i), {"i": i})
        await test_session.commit()

    envelope = (await authenticated_client.get("/api/audit/export/chain")).json()
    # Mutate a payload field without fixing the stored hash.
    envelope["rows"][1]["action"] = "TAMPERED"

    proc = subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"],
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
        cwd="/app",
        env=_VERIFIER_ENV,
    )
    assert proc.returncode == 1
    assert "BROKEN" in proc.stderr


@pytest.mark.asyncio
async def test_cli_refuses_without_key(authenticated_client, test_session, test_user):
    """No HMAC key available -> CLI exits non-zero instead of silently passing."""
    await audit_log(test_session, test_user.id, "a", "rule", "1", {"i": 1})
    await test_session.commit()
    envelope = (await authenticated_client.get("/api/audit/export/chain")).json()

    # Strip both key env vars so the verifier has no key to derive from.
    no_key_env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("CHAD_AUDIT_HMAC_KEY", "CHAD_ENCRYPTION_KEY")
    }
    proc = subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"],
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
        cwd="/app",
        env=no_key_env,
    )
    assert proc.returncode == 1
    assert "CANNOT VERIFY" in proc.stderr
