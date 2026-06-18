"""Unit tests for OrgScopeMiddleware (Host -> org contextvar wiring)."""

import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.org_constants import DEFAULT_ORG_ID
from app.core.org_context import get_org_id
from app.core.org_middleware import OrgScopeMiddleware
from app.models.organization import Organization


def _app_capturing_scope() -> FastAPI:
    """Tiny app behind the middleware that echoes the active org scope."""
    app = FastAPI()
    app.add_middleware(OrgScopeMiddleware)

    @app.get("/whoami")
    async def whoami():
        oid = get_org_id()
        return {"org_id": str(oid) if oid else None}

    return app


@pytest.mark.asyncio
async def test_unknown_host_falls_back_to_default_org(test_session):
    app = _app_capturing_scope()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as ac:
        resp = await ac.get("/whoami")
    assert resp.status_code == 200
    assert resp.json()["org_id"] == str(DEFAULT_ORG_ID)


@pytest.mark.asyncio
async def test_known_slug_host_resolves_to_that_org(test_session):
    org = Organization(id=uuid.uuid4(), name="Acme", slug="acmeorg")
    test_session.add(org)
    await test_session.commit()

    app = _app_capturing_scope()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://acmeorg.chad.example.com"
    ) as ac:
        resp = await ac.get("/whoami")
    assert resp.json()["org_id"] == str(org.id)


@pytest.mark.asyncio
async def test_scope_is_cleared_after_request(test_session):
    app = _app_capturing_scope()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as ac:
        await ac.get("/whoami")
    # Outside the request, the contextvar must be back to None (no leak).
    assert get_org_id() is None
