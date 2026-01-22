"""
Audit logging service for tracking user actions.

Usage:
    from app.services.audit import audit_log
    await audit_log(db, user_id, "rule.create", "rule", rule.id, {"title": rule.title})
"""
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def audit_log(
    db: AsyncSession,
    user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Create an audit log entry.

    Args:
        db: Database session
        user_id: User performing the action (None for system actions)
        action: Action type (e.g., "rule.create", "user.login")
        resource_type: Type of resource (e.g., "rule", "user", "settings")
        resource_id: ID of the affected resource
        details: Additional context

    Returns:
        Created AuditLog entry
    """
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    db.add(log)
    # Don't commit here - let the caller manage the transaction
    return log
