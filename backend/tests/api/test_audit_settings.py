"""Tests for the audit hardening settings API."""

import uuid
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role) -> User:
    user = User(
        id=uuid.uuid4(), email=email,
        password_hash=get_password_hash("pw-12345678"), role=role, is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_non_admin_forbidden(client, test_session):
    analyst = await _make_user(test_session, "a@example.com", UserRole.ANALYST)
    assert (await client.get("/api/audit-settings", headers=_auth(analyst))).status_code == 403


@pytest.mark.asyncio
async def test_admin_get_defaults(client, test_session):
    admin = await _make_user(test_session, "admin@example.com", UserRole.ADMIN)
    resp = await client.get("/api/audit-settings", headers=_auth(admin))
    assert resp.status_code == 200
    body = resp.json()
    assert body["retention_days"] == 0
    assert body["forward"]["has_header_value"] is False


@pytest.mark.asyncio
async def test_forward_requires_url(client, test_session):
    admin = await _make_user(test_session, "admin2@example.com", UserRole.ADMIN)
    resp = await client.put(
        "/api/audit-settings", headers=_auth(admin),
        json={"retention_days": 0, "forward": {"enabled": True}, "redaction": {"enabled": False, "fields": []}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_forward_rejects_invalid_url_scheme(client, test_session):
    # Scheme validation is environment-independent (SSRF IP blocking depends on
    # ALLOW_INTERNAL_WEBHOOK_IPS, which dev sets true). A non-http(s) scheme is
    # always rejected, exercising the same validation path.
    admin = await _make_user(test_session, "admin3@example.com", UserRole.ADMIN)
    resp = await client.put(
        "/api/audit-settings", headers=_auth(admin),
        json={"retention_days": 0,
              "forward": {"enabled": True, "url": "ftp://siem.internal/ingest"},
              "redaction": {"enabled": False, "fields": []}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_header_value_write_only(client, test_session):
    admin = await _make_user(test_session, "admin4@example.com", UserRole.ADMIN)
    # Bypass the fail-closed webhook DNS/SSRF guard so this settings test does not depend on
    # live DNS resolution of the forward URL host.
    with patch.object(settings, "ALLOW_INTERNAL_WEBHOOK_IPS", True):
        resp = await client.put(
            "/api/audit-settings", headers=_auth(admin),
            json={"retention_days": 90,
                  "forward": {"enabled": True, "url": "https://siem.example.com/ingest",
                              "format": "cef", "header_name": "Authorization", "header_value": "Bearer secret"},
                  "redaction": {"enabled": True, "fields": ["email"]}},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["retention_days"] == 90
    assert body["forward"]["has_header_value"] is True
    assert "header_value" not in body["forward"]  # never returned
    assert body["redaction"]["enabled"] is True
