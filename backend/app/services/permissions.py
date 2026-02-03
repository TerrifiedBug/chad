"""
Permission checking service.

Handles role-based permission checks and permission management.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role_permission import DEFAULT_ROLE_PERMISSIONS, RolePermission
from app.models.user import User


async def get_role_permissions(db: AsyncSession, role: str) -> dict[str, bool]:
    """Get all permissions for a role, with defaults applied."""
    # Start with defaults
    defaults = DEFAULT_ROLE_PERMISSIONS.get(role, {})
    permissions = dict(defaults)

    # Override with any customizations from database
    result = await db.execute(
        select(RolePermission).where(RolePermission.role == role)
    )
    for perm in result.scalars():
        permissions[perm.permission] = perm.granted

    return permissions


async def has_permission(db: AsyncSession, user: User, permission: str) -> bool:
    """Check if a user has a specific permission."""
    # Admin always has all permissions
    if user.role == "admin":
        return True

    permissions = await get_role_permissions(db, user.role)
    return permissions.get(permission, False)


async def set_role_permission(
    db: AsyncSession,
    role: str,
    permission: str,
    granted: bool,
) -> None:
    """Set a permission for a role."""
    # Don't allow modifying admin permissions
    if role == "admin":
        return

    result = await db.execute(
        select(RolePermission).where(
            RolePermission.role == role,
            RolePermission.permission == permission,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.granted = granted
    else:
        db.add(RolePermission(role=role, permission=permission, granted=granted))

    await db.commit()


async def get_all_role_permissions(db: AsyncSession) -> dict[str, dict[str, bool]]:
    """Get permissions for all roles."""
    return {
        "admin": await get_role_permissions(db, "admin"),
        "analyst": await get_role_permissions(db, "analyst"),
        "viewer": await get_role_permissions(db, "viewer"),
    }
