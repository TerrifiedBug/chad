"""
Role permissions API endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.models.role_permission import PERMISSION_DESCRIPTIONS
from app.services.permissions import get_all_role_permissions, set_role_permission
from app.services.audit import audit_log

router = APIRouter(prefix="/permissions", tags=["permissions"])


class PermissionUpdate(BaseModel):
    role: str
    permission: str
    granted: bool


class PermissionsResponse(BaseModel):
    roles: dict[str, dict[str, bool]]
    descriptions: dict[str, str]


@router.get("", response_model=PermissionsResponse)
async def get_permissions(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get all role permissions."""
    roles = await get_all_role_permissions(db)
    return PermissionsResponse(roles=roles, descriptions=PERMISSION_DESCRIPTIONS)


@router.put("")
async def update_permission(
    data: PermissionUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Update a role permission."""
    if data.role == "admin":
        return {"error": "Cannot modify admin permissions"}

    await set_role_permission(db, data.role, data.permission, data.granted)
    await audit_log(
        db, current_user.id, "permission.update", "role_permission", None,
        {"role": data.role, "permission": data.permission, "granted": data.granted}
    )

    return {"success": True}
