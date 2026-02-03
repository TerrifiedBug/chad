"""
Utility decorators for reducing code duplication in API endpoints.

Provides common patterns for:
- Audit logging
- Permission checking
- Error handling
"""
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.models.user import User
from app.services.audit import audit_log

P = ParamSpec("P")
R = TypeVar("R")


def with_audit_log(
    action: str,
    resource_type: str,
    get_resource_id: Callable[..., str] | None = None,
):
    """
    Decorator to automatically add audit logging to endpoints.

    Args:
        action: Action being performed (e.g., "create", "update", "delete")
        resource_type: Type of resource (e.g., "rule", "user")
        get_resource_id: Optional function to extract resource ID from kwargs

    Example:
        @with_audit_log("create", "rule", lambda kwargs: kwargs["rule_id"])
        async def create_rule(rule_id: str, ...):
            ...
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Extract common parameters
            request: Request | None = kwargs.get("request")
            db: AsyncSession | None = kwargs.get("db")
            current_user: User | None = kwargs.get("current_user")

            # Call the original function
            result = await func(*args, **kwargs)

            # Log audit event if we have the required parameters
            if request and db and current_user:
                resource_id = get_resource_id(**kwargs) if get_resource_id else None
                await audit_log(
                    db,
                    current_user.id,
                    f"{action}.{resource_type}",
                    resource_type,
                    resource_id or "unknown",
                    kwargs,
                    get_client_ip(request),
                )

            return result

        return wrapper

    return decorator


def require_permission(permission: str):
    """
    Dependency injection for permission checking.

    Usage:
        @router.get("/rules")
        async def list_rules(
            _: Annotated[User, Depends(require_permission("view_rules"))],
        ):
            ...

    This is equivalent to:
        from app.api.deps import require_permission_dep
        Depends(require_permission_dep("view_rules"))

    But with a shorter, more readable syntax.
    """
    from app.api.deps import require_permission_dep
    return require_permission_dep(permission)


def authenticated():
    """
    Dependency injection for authenticated user.

    Usage:
        @router.get("/profile")
        async def get_profile(
            user: Annotated[User, Depends(authenticated())],
        ):
            ...
    """
    return get_current_user


def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request.

    Handles X-Forwarded-For header for proxied requests.
    """
    from app.utils.request import get_client_ip as _get_client_ip
    return _get_client_ip(request)


# Commonly used permission dependencies
class Permissions:
    """Shortcut for common permission dependencies."""

    MANAGE_RULES = require_permission("manage_rules")
    VIEW_RULES = require_permission("view_rules")
    MANAGE_USERS = require_permission("manage_users")
    MANAGE_API_KEYS = require_permission("manage_api_keys")
    VIEW_AUDIT = require_permission("view_audit")
    MANAGE_SETTINGS = require_permission("manage_settings")
    MANAGE_ALERTS = require_permission("manage_alerts")
    VIEW_ALERTS = require_permission("view_alerts")


class CurrentUser:
    """Shortcut for getting current authenticated user."""

    GET = authenticated()

    # With specific permissions
    ADMIN = require_permission("admin")
    MANAGE_RULES = Permissions.MANAGE_RULES
    MANAGE_USERS = Permissions.MANAGE_USERS
    MANAGE_ALERTS = Permissions.MANAGE_ALERTS
