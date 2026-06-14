"""Idempotent SSO group -> team + role reconciliation.

This module is the SINGLE writer of group-sourced team membership AND of
group-sourced role. Given the set of IdP-asserted group values for a user, it
derives the desired team + role from the provider's ``sso_group_mappings`` and
applies it to ``User`` — but ONLY when a mapping actually matched.

CHAD single-team policy: ``User.team_id`` is one FK, so the highest-priority
matched team wins (ADMIN > ANALYST > VIEWER). Multi-team membership is Phase 2.

Provenance rules (close the manual-clobber + privilege vectors):
- A team set by ``team_source='group_mapping'`` is owned here and re-derived on
  every login.
- A team set manually (``team_source='manual'`` or NULL legacy) is NEVER
  overridden when no group matches. When a group DOES match, the group mapping
  wins (the IdP is authoritative for group-driven membership) and the source
  flips to ``group_mapping``.
- **Role is only ever written when a group mapping matched.** When no group
  matches (empty/absent groups claim, or only unknown groups) the user's role is
  left exactly as-is — reconciliation never demotes an existing user to the
  provider default and never clobbers a manually-set role. Role-claim / default
  role for *new* users is decided by the caller, not here.
"""

import logging
from typing import NamedTuple

from app.models.sso_provider import SSOProvider
from app.models.user import TeamSource, User, UserRole

logger = logging.getLogger(__name__)

# Role precedence: higher index == higher privilege. Used to pick the winning
# mapping when a user matches several groups.
_ROLE_PRIORITY = {
    UserRole.VIEWER: 0,
    UserRole.ANALYST: 1,
    UserRole.ADMIN: 2,
}


class ReconcileResult(NamedTuple):
    """Outcome of a reconciliation pass.

    Attributes:
        changed: whether any attribute (team_id / role / team_source) changed.
        group_matched: whether at least one group mapping matched.
        admin_granted_via_group: a group mapping granted ADMIN this pass (the
            caller should emit an audit row for the privileged promotion).
    """

    changed: bool
    group_matched: bool
    admin_granted_via_group: bool


def _coerce_role(value: str | UserRole | None) -> UserRole | None:
    """Best-effort coerce a stored role string to UserRole; None if unknown."""
    if value is None:
        return None
    if isinstance(value, UserRole):
        return value
    try:
        return UserRole(str(value).lower())
    except ValueError:
        return None


def reconcile_user_team_memberships(
    user: User,
    group_values: list[str] | None,
    provider: SSOProvider,
) -> ReconcileResult:
    """Reconcile ``user``'s team + role from their IdP group values.

    Idempotent: calling repeatedly with the same inputs yields the same state.
    Does NOT commit — the caller owns the transaction.

    Args:
        user: the user being reconciled (mutated in place).
        group_values: IdP-asserted group values (any case). May be None/empty.
        provider: the SSO provider, with ``group_mappings`` loaded.

    Returns:
        A :class:`ReconcileResult`.
    """
    normalized = {str(g).strip().lower() for g in (group_values or []) if str(g).strip()}

    # Find the highest-priority matching mapping.
    best_mapping = None
    best_priority = -1
    for mapping in provider.group_mappings:
        if str(mapping.group_value).strip().lower() not in normalized:
            continue
        role = _coerce_role(mapping.role) or UserRole.VIEWER
        priority = _ROLE_PRIORITY.get(role, 0)
        if priority > best_priority:
            best_priority = priority
            best_mapping = mapping

    group_matched = best_mapping is not None
    admin_granted_via_group = False

    if group_matched:
        # A group matched: the IdP is authoritative for team AND role.
        desired_team_id = best_mapping.team_id
        desired_role = _coerce_role(best_mapping.role) or UserRole.VIEWER
        desired_source: str | None = TeamSource.GROUP_MAPPING.value
        if desired_role == UserRole.ADMIN and user.role != UserRole.ADMIN:
            admin_granted_via_group = True
    else:
        # No group matched. Team falls back to the provider default, but NEVER
        # clobbers a manually-assigned team. ROLE is left untouched entirely —
        # reconciliation is not allowed to demote/escalate on a non-match.
        if user.team_source == TeamSource.MANUAL.value or (
            user.team_source is None and user.team_id is not None
        ):
            # Manual assignment is sacred: leave team_id + team_source as-is.
            desired_team_id = user.team_id
            desired_source = user.team_source
        else:
            desired_team_id = provider.default_team_id
            # A default-derived team is owned by reconciliation.
            desired_source = (
                TeamSource.GROUP_MAPPING.value if provider.default_team_id else None
            )
        desired_role = user.role  # untouched

    changed = False
    if user.team_id != desired_team_id:
        user.team_id = desired_team_id
        changed = True
    if user.team_source != desired_source:
        user.team_source = desired_source
        changed = True
    if user.role != desired_role:
        user.role = desired_role
        changed = True

    return ReconcileResult(
        changed=changed,
        group_matched=group_matched,
        admin_granted_via_group=admin_granted_via_group,
    )
