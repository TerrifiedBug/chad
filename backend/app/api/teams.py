"""Team management API (admin only).

Teams own resources (rules, index patterns) for resource-scoped RBAC. Only
admins can create/modify teams and assign members.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.team import Team
from app.models.user import User
from app.schemas.team import TeamCreate, TeamMemberAssign, TeamResponse, TeamUpdate
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/teams", tags=["teams"])


async def _get_team_or_404(db: AsyncSession, team_id: UUID) -> Team:
    team = (await db.execute(select(Team).where(Team.id == team_id))).scalar_one_or_none()
    if team is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
    return team


@router.get("", response_model=list[TeamResponse])
async def list_teams(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    result = await db.execute(select(Team).order_by(Team.name))
    return list(result.scalars().all())


@router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    data: TeamCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    team = Team(name=data.name, description=data.description)
    db.add(team)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A team with that name already exists"
        ) from None
    await db.refresh(team)
    await audit_log(
        db, admin.id, "team.create", "team", str(team.id),
        {"name": team.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return team


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    return await _get_team_or_404(db, team_id)


@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: UUID,
    data: TeamUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    team = await _get_team_or_404(db, team_id)
    if data.name is not None:
        team.name = data.name
    if data.description is not None:
        team.description = data.description
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A team with that name already exists"
        ) from None
    await db.refresh(team)
    await audit_log(
        db, admin.id, "team.update", "team", str(team.id),
        {"name": team.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return team


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    team = await _get_team_or_404(db, team_id)
    # Members + owned resources have ON DELETE SET NULL, so they become un-teamed.
    await db.delete(team)
    await audit_log(
        db, admin.id, "team.delete", "team", str(team_id),
        {"name": team.name}, ip_address=get_client_ip(request),
    )
    await db.commit()


@router.get("/{team_id}/members")
async def list_team_members(
    team_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    await _get_team_or_404(db, team_id)
    result = await db.execute(select(User).where(User.team_id == team_id))
    return [{"id": str(u.id), "email": u.email, "role": u.role.value} for u in result.scalars().all()]


@router.post("/{team_id}/members", status_code=status.HTTP_204_NO_CONTENT)
async def add_team_member(
    team_id: UUID,
    data: TeamMemberAssign,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    await _get_team_or_404(db, team_id)
    user = (await db.execute(select(User).where(User.id == data.user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.team_id = team_id
    await audit_log(
        db, admin.id, "team.member_add", "team", str(team_id),
        {"user_id": str(user.id)}, ip_address=get_client_ip(request),
    )
    await db.commit()


@router.delete("/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_team_member(
    team_id: UUID,
    user_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or user.team_id != team_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User is not in this team")
    user.team_id = None
    await audit_log(
        db, admin.id, "team.member_remove", "team", str(team_id),
        {"user_id": str(user.id)}, ip_address=get_client_ip(request),
    )
    await db.commit()
