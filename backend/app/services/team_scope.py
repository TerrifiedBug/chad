"""Resource-scoped RBAC helpers.

Admins see all resources. Non-admin users (analyst/viewer) see resources owned
by their own team plus global, un-owned resources (team_id IS NULL). Applied to
listing/reading team-ownable resources (rules, index patterns).
"""

from sqlalchemy import or_

from app.models.user import User, UserRole


def apply_team_scope(stmt, model, user: User):
    """Restrict a SELECT statement to resources visible to ``user``.

    - Admin: unchanged (sees everything).
    - Others: ``model.team_id == user.team_id OR model.team_id IS NULL``.
      A user with no team sees only global (un-owned) resources.
    """
    if user.role == UserRole.ADMIN:
        return stmt
    return stmt.where(or_(model.team_id == user.team_id, model.team_id.is_(None)))


def can_access_resource(resource, user: User) -> bool:
    """Whether ``user`` may access a single team-ownable ``resource`` instance."""
    if user.role == UserRole.ADMIN:
        return True
    team_id = getattr(resource, "team_id", None)
    return team_id is None or team_id == user.team_id
