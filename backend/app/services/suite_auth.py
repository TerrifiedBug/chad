"""Delegated-auth (VectorFlow suite session) user resolution.

Single place that turns validated VF session claims into a CHAD ``User``:
JIT provisioning by lowercased email (``provisioned_via='vectorflow'``,
audit ``auth.suite_link``) and per-request role re-sync from ``suite_role``.

Mirrors the OIDC-callback provisioning in ``app/api/auth.py`` (sso_callback,
lines 941-960): SSO-style account, no local password. Provenance rule for
role re-sync matches ``app/services/sso_reconcile.py``: a manually managed
user (``team_source='manual'``) is never clobbered.
"""

import logging

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vf_session import VfSessionClaims
from app.models.user import AuthMethod, ProvisionedVia, TeamSource, User, UserRole
from app.services.audit import audit_log
from app.services.scim import count_active_admins

logger = logging.getLogger(__name__)

# Fixed suite-role contract: admin -> admin, editor -> analyst, viewer -> viewer.
SUITE_ROLE_TO_CHAD: dict[str, UserRole] = {
    "admin": UserRole.ADMIN,
    "editor": UserRole.ANALYST,
    "viewer": UserRole.VIEWER,
}


async def resolve_vf_user(db: AsyncSession, claims: VfSessionClaims) -> User:
    """Resolve (and JIT-provision) the CHAD user for a validated VF session."""
    email = claims.email.lower()
    # Unknown suite_role values map to the least-privileged role.
    desired_role = SUITE_ROLE_TO_CHAD.get(claims.suite_role, UserRole.VIEWER)

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            email=email,
            password_hash=None,  # VF-linked users have no local password
            role=desired_role,
            auth_method=AuthMethod.SSO,
            provisioned_via=ProvisionedVia.VECTORFLOW.value,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        await audit_log(
            db, user.id, "auth.suite_link", "user", str(user.id),
            {
                "email": email,
                "provider": claims.provider,
                "suite_role": claims.suite_role,
            },
        )
        await db.commit()
        await db.refresh(user)
        return user

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    # Per-request role re-sync from suite_role. A manually managed user
    # (team_source='manual') is sacred — same provenance rule sso_reconcile
    # applies to group mappings.
    if user.team_source != TeamSource.MANUAL.value and user.role != desired_role:
        # Last-admin guard: never let a suite-side role sync demote the sole
        # active CHAD admin. Mirrors scim.py's can_scim_deactivate guard,
        # reusing the same count_active_admins helper.
        if user.role == UserRole.ADMIN and desired_role != UserRole.ADMIN:
            remaining_admins = await count_active_admins(db, exclude_user_id=user.id)
            if remaining_admins == 0:
                await audit_log(
                    db, user.id, "auth.suite_role_sync_blocked", "user", str(user.id),
                    {
                        "email": email,
                        "current_role": user.role.value,
                        "attempted_role": desired_role.value,
                        "reason": "last_active_admin",
                    },
                )
                await db.commit()
                await db.refresh(user)
                return user

        user.role = desired_role
        await db.commit()
        await db.refresh(user)

    return user
