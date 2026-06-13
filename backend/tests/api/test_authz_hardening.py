"""Authorization-hardening regression tests.

These pin the security fixes:
- Log-shipping auth tokens must not be exposed to users without manage_index_config.
- MISP sync (admin) and MISP feedback (manage_alerts) endpoints must enforce authz.
- /metrics must require a token when METRICS_TOKEN is configured.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from httpx import AsyncClient

from app.api.index_patterns import MASKED_AUTH_TOKEN


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestAuthTokenExposure:
    @pytest.mark.asyncio
    async def test_viewer_list_masks_auth_token(
        self, client: AsyncClient, normal_token: str, test_index_pattern
    ):
        """A viewer (no manage_index_config) must not see real log-shipping tokens."""
        resp = await client.get("/api/index-patterns", headers=_auth(normal_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data, "expected at least one index pattern"
        for pattern in data:
            assert pattern["auth_token"] == MASKED_AUTH_TOKEN

    @pytest.mark.asyncio
    async def test_viewer_get_masks_auth_token(
        self, client: AsyncClient, normal_token: str, test_index_pattern
    ):
        resp = await client.get(
            f"/api/index-patterns/{test_index_pattern.id}", headers=_auth(normal_token)
        )
        assert resp.status_code == 200
        assert resp.json()["auth_token"] == MASKED_AUTH_TOKEN

    @pytest.mark.asyncio
    async def test_admin_list_reveals_real_auth_token(
        self, client: AsyncClient, admin_token: str, test_index_pattern
    ):
        """Privileged users still receive the real token (no regression)."""
        resp = await client.get("/api/index-patterns", headers=_auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data
        token = data[0]["auth_token"]
        assert token != MASKED_AUTH_TOKEN
        assert token == test_index_pattern.auth_token


class TestMispAuthz:
    @pytest.mark.asyncio
    async def test_viewer_cannot_trigger_sync(self, client: AsyncClient, normal_token: str):
        # json={} sets a JSON Content-Type so the request passes the content-type
        # middleware and actually reaches the authorization check.
        resp = await client.post("/api/misp/sync/trigger", headers=_auth(normal_token), json={})
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_update_sync_config(self, client: AsyncClient, normal_token: str):
        resp = await client.put(
            "/api/misp/sync/config",
            headers=_auth(normal_token),
            json={"enabled": True, "interval_minutes": 10},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_record_sighting(self, client: AsyncClient, normal_token: str):
        resp = await client.post(
            "/api/misp/feedback/sighting",
            headers=_auth(normal_token),
            json={"attribute_uuid": "abc", "is_false_positive": True},
        )
        assert resp.status_code == 403


class TestMetricsTokenGate:
    @pytest.mark.asyncio
    async def test_metrics_rejects_without_token_when_configured(self, monkeypatch):
        from app.api import metrics as metrics_mod
        from app.core.config import settings

        monkeypatch.setattr(settings, "METRICS_TOKEN", "s3cret")
        with pytest.raises(HTTPException) as exc:
            await metrics_mod.metrics(authorization=None)
        assert exc.value.status_code == 401
        with pytest.raises(HTTPException):
            await metrics_mod.metrics(authorization="Bearer wrong")

    @pytest.mark.asyncio
    async def test_metrics_allows_with_correct_token(self, monkeypatch):
        from app.api import metrics as metrics_mod
        from app.core.config import settings

        monkeypatch.setattr(settings, "METRICS_TOKEN", "s3cret")
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        mock_redis.scan = AsyncMock(return_value=(0, []))
        mock_redis.xlen = AsyncMock(return_value=0)
        with patch("app.api.metrics.get_redis", return_value=mock_redis):
            result = await metrics_mod.metrics(authorization="Bearer s3cret")
        assert "chad_redis_connected 1" in result
