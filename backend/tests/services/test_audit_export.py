"""Tests for audit hardening: redaction, CEF rendering, retention purge."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.audit_log import AuditLog
from app.services.audit_export import (
    merge_audit_settings,
    purge_old_audit_logs,
    redact_pii,
    save_audit_settings,
    to_cef,
)


def test_merge_audit_settings_defaults():
    s = merge_audit_settings(None)
    assert s["retention_days"] == 0
    assert s["forward"]["enabled"] is False
    assert "email" in s["redaction"]["fields"]


def test_merge_audit_settings_overlay():
    s = merge_audit_settings({"retention_days": 30, "redaction": {"enabled": True, "fields": ["ip"]}})
    assert s["retention_days"] == 30
    assert s["redaction"]["enabled"] is True
    assert s["redaction"]["fields"] == ["ip"]


def test_redact_pii_nested_and_case_insensitive():
    details = {
        "Email": "a@b.com",
        "nested": {"user_email": "x@y.com", "safe": "keep"},
        "list": [{"ip_address": "1.2.3.4"}, {"other": "ok"}],
    }
    out = redact_pii(details, ["email", "user_email", "ip_address"])
    assert out["Email"] == "[REDACTED]"
    assert out["nested"]["user_email"] == "[REDACTED]"
    assert out["nested"]["safe"] == "keep"
    assert out["list"][0]["ip_address"] == "[REDACTED]"
    assert out["list"][1]["other"] == "ok"
    # Original is untouched.
    assert details["Email"] == "a@b.com"


def test_redact_pii_none():
    assert redact_pii(None, ["email"]) is None


def test_to_cef_contains_action_and_extension():
    log = AuditLog(
        id=uuid.uuid4(), user_id=uuid.uuid4(), action="rule.deploy",
        resource_type="rule", resource_id="r1", ip_address="10.0.0.1",
        details={"title": "X"}, created_at=datetime(2026, 6, 15, tzinfo=UTC),
    )
    line = to_cef(log, {"title": "X"})
    assert line.startswith("CEF:0|CHAD|CHAD|1|rule.deploy|")
    assert "act=rule.deploy" in line
    assert "src=10.0.0.1" in line


@pytest.mark.asyncio
async def test_purge_respects_retention(test_session):
    # retention disabled by default → no purge
    old = AuditLog(
        id=uuid.uuid4(), action="x", resource_type="y",
        created_at=datetime.now(UTC) - timedelta(days=400),
    )
    recent = AuditLog(
        id=uuid.uuid4(), action="x", resource_type="y",
        created_at=datetime.now(UTC),
    )
    test_session.add_all([old, recent])
    await test_session.commit()

    assert await purge_old_audit_logs(test_session) == 0  # disabled

    await save_audit_settings(test_session, {"retention_days": 365})
    purged = await purge_old_audit_logs(test_session)
    assert purged == 1  # only the 400-day-old row
