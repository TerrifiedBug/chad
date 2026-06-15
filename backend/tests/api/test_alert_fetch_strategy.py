"""Regression tests pinning the alert-list fetch strategy.

The ``GET /alerts`` endpoint deliberately widens the OpenSearch fetch window
when clustering or an owner filter is active so the service sees the full
candidate set (see ``ALERT_WIDE_FETCH_LIMIT`` in ``app.api.alerts``). These
tests assert the ``limit``/``offset`` actually handed to the query layer so a
future refactor can't silently change that behavior. They mock the query layer
(``AlertService.get_alerts``) rather than touching its internals.
"""

import uuid

import pytest

from app.api import alerts as alerts_api
from app.api.alerts import ALERT_WIDE_FETCH_LIMIT
from app.api.deps import get_opensearch_client
from app.core.security import create_access_token, get_password_hash
from app.main import app
from app.models.user import User, UserRole
from app.services.alerts import AlertService


class _StubOpenSearch:
    """Placeholder client; AlertService.get_alerts is patched so it's unused."""


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(data={'sub': str(user.id)})}"}


async def _make_user(session, email, role=UserRole.ANALYST) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=get_password_hash("pw-12345678"),
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@pytest.fixture
def stub_os():
    fake = _StubOpenSearch()
    app.dependency_overrides[get_opensearch_client] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_opensearch_client, None)


@pytest.fixture
def capture_fetch(monkeypatch):
    """Capture the limit/offset the endpoint passes to the query layer.

    Patches ``AlertService.get_alerts`` — the single method both the cached and
    direct paths funnel through — so we observe the real fetch strategy without
    depending on Redis being up.
    """
    calls: list[dict] = []

    def fake_get_alerts(self, *args, **kwargs):
        calls.append({"limit": kwargs.get("limit"), "offset": kwargs.get("offset")})
        return {"total": 0, "alerts": []}

    monkeypatch.setattr(AlertService, "get_alerts", fake_get_alerts)
    return calls


def _clustering(enabled: bool):
    async def _get_setting(db, key):
        if key == "alert_clustering":
            return {"enabled": enabled}
        return None

    return _get_setting


@pytest.mark.asyncio
async def test_clustering_widens_fetch_to_constant_at_offset_zero(
    client, test_session, stub_os, capture_fetch, monkeypatch
):
    """Clustering enabled -> fetch ALERT_WIDE_FETCH_LIMIT at offset 0,
    ignoring the caller's limit/offset."""
    monkeypatch.setattr(alerts_api, "get_setting", _clustering(True))
    user = await _make_user(test_session, "cluster@example.com")

    resp = await client.get(
        "/api/alerts?limit=25&offset=50&cluster=true",
        headers=_auth(user),
    )
    assert resp.status_code == 200, resp.text
    assert capture_fetch, "AlertService.get_alerts was never called"
    assert capture_fetch[-1] == {"limit": ALERT_WIDE_FETCH_LIMIT, "offset": 0}


@pytest.mark.asyncio
async def test_owner_filter_widens_fetch_to_constant_at_offset_zero(
    client, test_session, stub_os, capture_fetch, monkeypatch
):
    """Owner filter set (clustering off) -> fetch ALERT_WIDE_FETCH_LIMIT at
    offset 0, ignoring the caller's limit/offset."""
    monkeypatch.setattr(alerts_api, "get_setting", _clustering(False))
    user = await _make_user(test_session, "owner@example.com")

    resp = await client.get(
        "/api/alerts?limit=25&offset=50&owner=me&cluster=false",
        headers=_auth(user),
    )
    assert resp.status_code == 200, resp.text
    assert capture_fetch, "AlertService.get_alerts was never called"
    assert capture_fetch[-1] == {"limit": ALERT_WIDE_FETCH_LIMIT, "offset": 0}


@pytest.mark.asyncio
async def test_default_path_uses_exact_requested_window(
    client, test_session, stub_os, capture_fetch, monkeypatch
):
    """No clustering, no owner filter -> fetch exactly the requested
    limit/offset (no widening)."""
    monkeypatch.setattr(alerts_api, "get_setting", _clustering(False))
    user = await _make_user(test_session, "default@example.com")

    resp = await client.get(
        "/api/alerts?limit=25&offset=50&cluster=false",
        headers=_auth(user),
    )
    assert resp.status_code == 200, resp.text
    assert capture_fetch, "AlertService.get_alerts was never called"
    assert capture_fetch[-1] == {"limit": 25, "offset": 50}
