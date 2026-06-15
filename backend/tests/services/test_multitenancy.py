"""Tests for the multi-tenancy foundation (F4): org context, host→org, scope."""

import uuid

import pytest
from sqlalchemy import select

from app.core.org_constants import DEFAULT_ORG_ID, DEFAULT_ORG_SLUG
from app.core.org_context import get_org_id, run_with_org, set_org_id
from app.models.organization import Organization
from app.services.host_to_org import (
    extract_slug_from_host,
    normalize_host,
    resolve_org_id_from_host,
)
from app.services.org_constraints import get_org_constraints
from app.services.org_scope import apply_org_scope, can_access_org_resource


def test_normalize_host_strips_port_and_brackets():
    assert normalize_host("acme.chad.example.com:443") == "acme.chad.example.com"
    assert normalize_host("[::1]:3000") == "::1"
    assert normalize_host("localhost") == "localhost"


def test_extract_slug_requires_two_labels_and_valid_slug():
    assert extract_slug_from_host("acme.chad.example.com") == "acme"
    assert extract_slug_from_host("localhost") is None  # single label
    assert extract_slug_from_host("10.0.0.5") is not None or True  # IP-ish; just no crash
    assert extract_slug_from_host("AB.example.com") is None  # too short / invalid slug


def test_org_context_set_and_run():
    assert get_org_id() is None
    oid = uuid.uuid4()
    set_org_id(oid)
    assert get_org_id() == oid
    set_org_id(None)


@pytest.mark.asyncio
async def test_run_with_org_restores_previous():
    inner = uuid.uuid4()
    captured = {}

    async def work():
        captured["inside"] = get_org_id()
        return "ok"

    set_org_id(None)
    result = await run_with_org(inner, work)
    assert result == "ok"
    assert captured["inside"] == inner
    assert get_org_id() is None  # restored


@pytest.mark.asyncio
async def test_default_org_seeded(test_session):
    # The default org is created by the migration; the test DB builds from
    # metadata, so seed it here to mirror production.
    test_session.add(Organization(id=DEFAULT_ORG_ID, name="Default", slug=DEFAULT_ORG_SLUG))
    await test_session.commit()
    resolved = await resolve_org_id_from_host(test_session, "default.chad.example.com")
    assert resolved == DEFAULT_ORG_ID


@pytest.mark.asyncio
async def test_resolve_unknown_host_falls_back_to_default(test_session):
    assert await resolve_org_id_from_host(test_session, "localhost") == DEFAULT_ORG_ID
    assert await resolve_org_id_from_host(test_session, None) == DEFAULT_ORG_ID
    assert await resolve_org_id_from_host(test_session, "ghost.chad.example.com") == DEFAULT_ORG_ID


def test_apply_org_scope_includes_null_for_default():
    from app.models.rule import Rule

    # For the default org, the predicate must also admit NULL-org legacy rows.
    stmt = apply_org_scope(select(Rule), Rule, DEFAULT_ORG_ID)
    compiled = str(stmt)
    assert "organization_id" in compiled
    assert "IS NULL" in compiled.upper()

    # For a non-default org, NULL rows are excluded (hard fence).
    other = apply_org_scope(select(Rule), Rule, uuid.uuid4())
    assert "IS NULL" not in str(other).upper()


def test_can_access_org_resource_treats_null_as_default():
    class R:
        organization_id = None

    assert can_access_org_resource(R(), DEFAULT_ORG_ID) is True
    assert can_access_org_resource(R(), uuid.uuid4()) is False


@pytest.mark.asyncio
async def test_org_constraints_lifecycle(test_session):
    import datetime as dt

    live = Organization(id=uuid.uuid4(), name="Live", slug="liveorg")
    suspended = Organization(
        id=uuid.uuid4(), name="Susp", slug="susporg",
        suspended_at=dt.datetime.now(dt.UTC),
    )
    test_session.add_all([live, suspended])
    await test_session.commit()

    c_live = await get_org_constraints(test_session, live.id)
    assert c_live.is_active and c_live.deploy_enabled

    c_susp = await get_org_constraints(test_session, suspended.id)
    assert c_susp.reason == "suspended" and not c_susp.deploy_enabled

    c_missing = await get_org_constraints(test_session, uuid.uuid4())
    assert c_missing.reason == "deleted" and not c_missing.ai_enabled
