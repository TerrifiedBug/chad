"""
Role permissions API endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.role_permission import PERMISSION_DESCRIPTIONS
from app.models.user import User
from app.services.audit import audit_log
from app.services.permissions import get_all_role_permissions, set_role_permission
from app.utils.request import get_client_ip

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
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Update a role permission."""
    # Validate role
    if data.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be admin, analyst, or viewer."
        )

    # Admin permissions cannot be modified
    if data.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify admin permissions"
        )

    # Validate permission exists
    if data.permission not in PERMISSION_DESCRIPTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission. Valid permissions: {', '.join(PERMISSION_DESCRIPTIONS.keys())}"
        )

    await set_role_permission(db, data.role, data.permission, data.granted)
    await audit_log(
        db, current_user.id, "permission.update", "role_permission", None,
        {"role": data.role, "permission": data.permission, "granted": data.granted},
        ip_address=get_client_ip(request),
    )

    return {"success": True}
