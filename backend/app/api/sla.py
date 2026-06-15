"""SLA policy API — per-severity triage time targets.

Any authenticated user can read the policy (the alert UI derives due/breach
badges from it). Only admins can change it.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.sla import SlaPolicyResponse, SlaPolicyUpdate
from app.services.audit import audit_log
from app.services.sla import get_sla_policy, save_sla_policy
from app.utils.request import get_client_ip

router = APIRouter(prefix="/sla-policy", tags=["sla"])


@router.get("", response_model=SlaPolicyResponse)
async def read_sla_policy(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    return await get_sla_policy(db)


@router.put("", response_model=SlaPolicyResponse)
async def update_sla_policy(
    data: SlaPolicyUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    stored = await save_sla_policy(
        db, {"enabled": data.enabled, "targets_minutes": data.targets_minutes.model_dump()}
    )
    await audit_log(
        db, admin.id, "sla_policy.update", "setting", "sla_policy",
        {"enabled": stored["enabled"]}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return stored
