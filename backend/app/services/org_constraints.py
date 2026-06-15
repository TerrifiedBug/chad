"""Per-organization constraint engine (lifecycle gating).

Mirrors VectorFlow's org-constraints: resolve an org's lifecycle state and which
risky operations are allowed. A suspended or soft-deleted tenant has its
mutating capabilities turned off (read-mostly), so an operator can freeze a
tenant without deleting data.

Resolution precedence (highest → lowest): deleted → suspended → live.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization


@dataclass
class OrgConstraints:
    reason: str  # live | suspended | deleted
    plan: str | None
    ai_enabled: bool
    git_sync_enabled: bool
    deploy_enabled: bool
    notifications_enabled: bool

    @property
    def is_active(self) -> bool:
        return self.reason == "live"


_ALL_OFF = dict(
    ai_enabled=False, git_sync_enabled=False, deploy_enabled=False, notifications_enabled=False
)
_ALL_ON = dict(
    ai_enabled=True, git_sync_enabled=True, deploy_enabled=True, notifications_enabled=True
)


async def get_org_constraints(db: AsyncSession, organization_id: uuid.UUID) -> OrgConstraints:
    """Resolve the constraint set for an org (cheap single indexed read).

    Callers should not memoise across requests: suspension can flip mid-session.
    A missing org row is treated as deleted (deny risky ops).
    """
    org = (
        await db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
    ).scalar_one_or_none()

    if org is None or org.deleted_at is not None:
        return OrgConstraints(reason="deleted", plan=getattr(org, "plan", None), **_ALL_OFF)
    if org.suspended_at is not None:
        return OrgConstraints(reason="suspended", plan=org.plan, **_ALL_OFF)
    return OrgConstraints(reason="live", plan=org.plan, **_ALL_ON)
