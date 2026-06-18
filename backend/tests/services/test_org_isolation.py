"""Cross-org leakage tests for the rules tenancy fence.

These are the security-critical assertions: a request scoped to org A must
never read org B's rules, and a default-org request must still see legacy
NULL-org rows (OSS single-tenant behaviour).
"""

import uuid

import pytest
from sqlalchemy import select

from app.core.org_constants import DEFAULT_ORG_ID, DEFAULT_ORG_SLUG
from app.core.org_context import set_org_id
from app.models.organization import Organization
from app.models.rule import RuleStatus
from app.models.user import User, UserRole
from app.services.org_scope import apply_org_scope


async def _seed_orgs_and_rules(test_session):
    """Two real orgs + a default org, each owning one rule, plus a legacy
    NULL-org rule. Returns (org_a, org_b)."""
    from app.models.index_pattern import IndexPattern
    from app.models.rule import Rule

    default_org = Organization(id=DEFAULT_ORG_ID, name="Default", slug=DEFAULT_ORG_SLUG)
    org_a = Organization(id=uuid.uuid4(), name="A", slug="orgaaa")
    org_b = Organization(id=uuid.uuid4(), name="B", slug="orgbbb")
    test_session.add_all([default_org, org_a, org_b])
    await test_session.commit()

    creator = User(
        id=uuid.uuid4(), email="creator@example.com",
        password_hash="x", role=UserRole.ADMIN, is_active=True,
    )
    ip = IndexPattern(
        id=uuid.uuid4(), name="logs-*", pattern="logs-*",
        percolator_index="percolator-logs",
    )
    test_session.add_all([creator, ip])
    await test_session.commit()

    def _rule(title, org_id):
        return Rule(
            id=uuid.uuid4(), title=title, status=RuleStatus.UNDEPLOYED,
            index_pattern_id=ip.id, created_by=creator.id, organization_id=org_id,
            yaml_content="title: x\ndetection:\n  condition: x",
        )

    test_session.add_all([
        _rule("a-rule", org_a.id),
        _rule("b-rule", org_b.id),
        _rule("legacy-rule", None),
    ])
    await test_session.commit()
    return org_a, org_b


@pytest.mark.asyncio
async def test_apply_org_scope_fences_other_org_rows(test_session):
    """ORM-layer fence: org A scope returns only A's rule, never B's."""
    from app.models.rule import Rule

    org_a, org_b = await _seed_orgs_and_rules(test_session)

    a_rows = (await test_session.execute(
        apply_org_scope(select(Rule), Rule, org_a.id)
    )).scalars().all()
    a_titles = {r.title for r in a_rows}
    assert "a-rule" in a_titles
    assert "b-rule" not in a_titles      # hard fence
    assert "legacy-rule" not in a_titles  # NULL belongs to DEFAULT, not A


@pytest.mark.asyncio
async def test_apply_org_scope_default_sees_legacy_null_rows(test_session):
    """Default-org scope still sees NULL-org legacy rows (OSS behaviour)."""
    from app.models.rule import Rule

    await _seed_orgs_and_rules(test_session)
    rows = (await test_session.execute(
        apply_org_scope(select(Rule), Rule, DEFAULT_ORG_ID)
    )).scalars().all()
    titles = {r.title for r in rows}
    assert "legacy-rule" in titles
    assert "a-rule" not in titles
    assert "b-rule" not in titles
    set_org_id(None)
