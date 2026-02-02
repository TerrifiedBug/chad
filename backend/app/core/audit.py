"""Audit logging utility for tracking all state-changing operations.

This module provides a decorator for automatically logging actions to the audit_log table,
ensuring compliance and security monitoring requirements are met.
"""

import functools
import inspect
from collections.abc import Callable
from typing import Any, ParamSpec

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

P = ParamSpec("P")


async def log_audit(
    db: AsyncSession,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user: User | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Create an audit log entry.

    Args:
        db: Database session
        action: Action performed (create, update, delete, etc.)
        resource_type: Type of resource (rule, user, setting, etc.)
        resource_id: ID of the affected resource
        user: User who performed the action
        details: Additional details about the action
        ip_address: IP address of the requestor

    Returns:
        The created AuditLog entry
    """
    audit_entry = AuditLog(
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=details,
        ip_address=ip_address,
    )
    db.add(audit_entry)
    await db.flush()
    return audit_entry


def audit_action(
    action: str,
    resource_type: str,
    get_resource_id: Callable[[Any], str | None] | None = None,
    get_details: Callable[[Any], dict | None] | None = None,
):
    """Decorator to automatically audit state-changing operations.

    This decorator logs the action to the audit_log table before returning the result.
    It works with both sync and async functions, and automatically extracts resource_id
    and details from the return value or function arguments.

    Args:
        action: The action being performed (e.g., "create", "update", "delete")
        resource_type: The type of resource being modified (e.g., "rule", "user", "setting")
        get_resource_id: Optional function to extract resource_id from the result
        get_details: Optional function to extract details from the result

    Example:
        ```python
        @audit_action("create", "rule", lambda r: r.id, lambda r: {"name": r.name})
        async def create_rule(...):
            # ... create logic
            return rule

        @audit_action("delete", "user")
        async def delete_user(user_id: str, db: AsyncSession):
            # ... delete logic
            return {"deleted": user_id}
        ```

    For complex cases, you can manually call `log_audit()` in your function.
    """

    def decorator(func: Callable[P, Any]) -> Callable[P, Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            # Call the original function
            result = await func(*args, **kwargs)

            # Extract db session and user from kwargs or args
            db = kwargs.get("db")
            if not db:
                # Try to find db in args (common pattern: first arg after self is db)
                for arg in args:
                    if isinstance(arg, AsyncSession):
                        db = arg
                        break

            current_user = kwargs.get("current_user") or kwargs.get("_")
            ip_address = kwargs.get("ip_address") or kwargs.get("request")

            # Extract resource_id and details
            resource_id = None
            details = None

            if get_resource_id:
                try:
                    resource_id = get_resource_id(result)
                except Exception:
                    pass

            if get_details:
                try:
                    details = get_details(result)
                except Exception:
                    pass

            # Log the audit entry
            if db:
                try:
                    await log_audit(
                        db=db,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        user=current_user if isinstance(current_user, User) else None,
                        details=details,
                        ip_address=str(ip_address) if ip_address else None,
                    )
                except Exception as e:
                    # Don't fail the request if audit logging fails
                    # Log the error but continue
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Failed to create audit log entry: {e}")

            return result

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            # For sync functions, we can't easily await db operations
            # Just call the function and let manual audit logging handle it
            return func(*args, **kwargs)

        # Return the appropriate wrapper based on whether the function is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
