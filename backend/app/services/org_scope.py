"""Organization-scoped query helpers (tenant isolation at the ORM layer).

Companion to app.services.team_scope. Where team_scope narrows within an org,
org_scope is the hard tenant fence: a request scoped to org X must never read
org Y's rows. Applied to SELECTs over org-ownable models (those with an
``organization_id`` column).

OSS / single-tenant: every row backfills to the default org and the active scope
is the default org, so these predicates are satisfied transparently.
"""

from __future__ import annotations

import uuid

from sqlalchemy import or_

from app.core.org_constants import DEFAULT_ORG_ID


def apply_org_scope(stmt, model, org_id: uuid.UUID | None):
    """Restrict a SELECT to rows owned by ``org_id`` (or the default org).

    A None ``org_id`` (un-wired path / boot) falls back to the default org so the
    query still returns the single-tenant data rather than nothing. Rows with a
    NULL ``organization_id`` (legacy rows, or new rows created by a path that
    hasn't been org-wired yet) are treated as belonging to the default org, so
    they stay visible to a default-org request and are never silently dropped.
    """
    effective = org_id or DEFAULT_ORG_ID
    if effective == DEFAULT_ORG_ID:
        return stmt.where(
            or_(model.organization_id == effective, model.organization_id.is_(None))
        )
    return stmt.where(model.organization_id == effective)


def can_access_org_resource(resource, org_id: uuid.UUID | None) -> bool:
    """Whether a request scoped to ``org_id`` may touch ``resource``."""
    effective = org_id or DEFAULT_ORG_ID
    res_org = getattr(resource, "organization_id", None)
    # Legacy rows with NULL org belong to the default org.
    return (res_org or DEFAULT_ORG_ID) == effective
