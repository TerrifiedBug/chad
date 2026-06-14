"""Saved views API — named, reusable list filter presets.

Visibility model (mirrors team scoping):
- A user always sees their own views.
- A user also sees ``is_shared`` views owned by teammates (same ``team_id``),
  plus globally-shared views (owner had no team).
Only the owner may update or delete a view.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.saved_view import SavedView
from app.models.user import User
from app.schemas.saved_view import (
    ALLOWED_RESOURCES,
    SavedViewCreate,
    SavedViewResponse,
    SavedViewUpdate,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/saved-views", tags=["saved-views"])


def _validate_resource(resource: str) -> None:
    if resource not in ALLOWED_RESOURCES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"resource must be one of {sorted(ALLOWED_RESOURCES)}",
        )


def _visible_filter(user: User):
    """SELECT predicate for views visible to ``user``."""
    own = SavedView.owner_id == user.id
    # Shared by a teammate, or globally shared (owner had no team).
    if user.team_id is not None:
        shared = and_(
            SavedView.is_shared.is_(True),
            or_(SavedView.team_id == user.team_id, SavedView.team_id.is_(None)),
        )
    else:
        shared = and_(SavedView.is_shared.is_(True), SavedView.team_id.is_(None))
    return or_(own, shared)


async def _get_owned_or_404(db: AsyncSession, view_id: UUID, user: User) -> SavedView:
    view = (
        await db.execute(select(SavedView).where(SavedView.id == view_id))
    ).scalar_one_or_none()
    if view is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved view not found")
    if view.owner_id != user.id:
        # Don't leak existence of teammates' views beyond what list already shows.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can only modify your own saved views"
        )
    return view


async def _clear_other_defaults(
    db: AsyncSession, *, owner_id: UUID, resource: str, keep_id: UUID | None
) -> None:
    stmt = (
        update(SavedView)
        .where(
            SavedView.owner_id == owner_id,
            SavedView.resource == resource,
            SavedView.is_default.is_(True),
        )
        .values(is_default=False)
    )
    if keep_id is not None:
        stmt = stmt.where(SavedView.id != keep_id)
    await db.execute(stmt)


@router.get("", response_model=list[SavedViewResponse])
async def list_saved_views(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    resource: Annotated[str | None, Query()] = None,
):
    stmt = select(SavedView).where(_visible_filter(user))
    if resource is not None:
        _validate_resource(resource)
        stmt = stmt.where(SavedView.resource == resource)
    stmt = stmt.order_by(SavedView.name)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("", response_model=SavedViewResponse, status_code=status.HTTP_201_CREATED)
async def create_saved_view(
    data: SavedViewCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    _validate_resource(data.resource)
    view = SavedView(
        name=data.name,
        resource=data.resource,
        owner_id=user.id,
        team_id=user.team_id,
        is_shared=data.is_shared,
        is_default=data.is_default,
        filters=data.filters,
    )
    db.add(view)
    if data.is_default:
        await db.flush()
        await _clear_other_defaults(
            db, owner_id=user.id, resource=data.resource, keep_id=view.id
        )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a saved view with that name for this resource",
        ) from None
    await db.refresh(view)
    await audit_log(
        db, user.id, "saved_view.create", "saved_view", str(view.id),
        {"name": view.name, "resource": view.resource, "shared": view.is_shared},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return view


@router.put("/{view_id}", response_model=SavedViewResponse)
async def update_saved_view(
    view_id: UUID,
    data: SavedViewUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    view = await _get_owned_or_404(db, view_id, user)
    if data.name is not None:
        view.name = data.name
    if data.filters is not None:
        view.filters = data.filters
    if data.is_shared is not None:
        view.is_shared = data.is_shared
    if data.is_default is not None:
        view.is_default = data.is_default
        if data.is_default:
            await _clear_other_defaults(
                db, owner_id=user.id, resource=view.resource, keep_id=view.id
            )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a saved view with that name for this resource",
        ) from None
    await db.refresh(view)
    await audit_log(
        db, user.id, "saved_view.update", "saved_view", str(view.id),
        {"name": view.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return view


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_view(
    view_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    view = await _get_owned_or_404(db, view_id, user)
    await db.delete(view)
    await audit_log(
        db, user.id, "saved_view.delete", "saved_view", str(view_id),
        {"name": view.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
