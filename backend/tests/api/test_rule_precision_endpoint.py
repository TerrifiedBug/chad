"""Endpoint test for GET /stats/rule-precision."""

import uuid
from unittest.mock import patch

import pytest

from app.core.security import create_access_token, get_password_hash
from app.models.user import User, UserRole


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role) -> User:
    user = User(id=uuid.uuid4(), email=email, password_hash=get_password_hash("pw-12345678"),
                role=role, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_rule_precision_requires_auth(client):
    resp = await client.get("/api/stats/rule-precision")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rule_precision_returns_rows(client, test_session):
    user = await _make_user(test_session, "analyst@example.com", UserRole.ANALYST)
    rows = [{
        "rule_id": "ioc-detection", "total": 5, "resolved": 1, "false_positive": 4,
        "open": 0, "precision_pct": 20.0, "fp_rate_pct": 80.0, "alerts_per_day": 0.2,
    }]
    with patch("app.api.stats.get_rule_precision", return_value=rows):
        resp = await client.get("/api/stats/rule-precision?days=14", headers=_auth(user))
    assert resp.status_code == 200
    body = resp.json()
    assert body["window_days"] == 14
    assert body["rules"][0]["rule_id"] == "ioc-detection"
    # Non-UUID rule_id falls back to the raw id as the title.
    assert body["rules"][0]["rule_title"] == "ioc-detection"
