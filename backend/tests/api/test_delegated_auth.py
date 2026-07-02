"""Delegated (VectorFlow session) auth funnel tests.

Covers the auth-funnel rework of app/api/deps.py: HTTPBearer(auto_error=False),
cookie-first delegated mode, JIT provisioning, per-request role re-sync, and
gating of CHAD-local auth surfaces when CHAD_DELEGATED_AUTH is on.
"""

import pytest
from httpx import AsyncClient


class TestBearerDependency:
    @pytest.mark.asyncio
    async def test_bearer_flow_still_works(self, authenticated_client: AsyncClient):
        """Existing token pattern (conftest authenticated_client) must be unchanged."""
        resp = await authenticated_client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["email"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_missing_credentials_is_401_not_403(self, client: AsyncClient):
        """HTTPBearer(auto_error=True) used to 403 before any cookie branch could run."""
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Not authenticated"
