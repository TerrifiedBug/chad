"""Gated bidirectional GitOps API (I6).

Inbound import is OFF by default and guarded by the ``gitops_inbound`` flag (the
operator sign-off). Import never deploys: it stages git rule changes as
undeployed draft versions that still require the normal deploy/approval flow.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_permission_dep
from app.db.session import get_db
from app.models.environment import Environment
from app.models.user import User
from app.services.audit import audit_log
from app.services.git.git_import import (
    GitImportError,
    apply_import,
    is_inbound_enabled,
    preview_import,
    set_inbound_enabled,
)
from app.utils.request import get_client_ip

router = APIRouter(prefix="/gitops", tags=["gitops"])


class InboundFlag(BaseModel):
    enabled: bool


class ImportApplyRequest(BaseModel):
    paths: list[str] = Field(min_length=1)


async def _get_env_or_404(db: AsyncSession, env_id: UUID) -> Environment:
    env = (await db.execute(select(Environment).where(Environment.id == env_id))).scalar_one_or_none()
    if env is None:
        raise HTTPException(status_code=404, detail="Environment not found")
    return env


@router.get("/inbound", response_model=InboundFlag)
async def get_inbound_flag(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    return InboundFlag(enabled=await is_inbound_enabled(db))


@router.put("/inbound", response_model=InboundFlag)
async def set_inbound_flag(
    data: InboundFlag,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    """Enable/disable inbound GitOps. This is the explicit operator sign-off that
    reverses the default push-only stance."""
    await set_inbound_enabled(db, data.enabled)
    await audit_log(
        db, admin.id, "gitops.inbound_flag", "setting", "gitops_inbound",
        {"enabled": data.enabled}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return InboundFlag(enabled=data.enabled)


@router.post("/environments/{env_id}/import-preview")
async def import_preview(
    env_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_environments"))],
):
    env = await _get_env_or_404(db, env_id)
    try:
        return await preview_import(db, env)
    except GitImportError as e:
        # Disabled flag / unconfigured repo → 409 (not a server error).
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from None


@router.post("/environments/{env_id}/import")
async def import_apply(
    env_id: UUID,
    data: ImportApplyRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    env = await _get_env_or_404(db, env_id)
    try:
        result = await apply_import(db, env, current_user.id, data.paths)
    except GitImportError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from None
    await audit_log(
        db, current_user.id, "gitops.import", "environment", str(env_id),
        {"updated": len(result["updated"]), "skipped": len(result["skipped"])},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return result
