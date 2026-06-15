"""Organization (tenant) management API — admin only.

Manage tenants for multi-tenant / MSSP deployments: create, list, update, and
suspend/restore/soft-delete orgs. OSS installs run with just the seeded default
org; this surface is inert there but available when running multi-tenant. The
default org cannot be deleted.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.org_constants import DEFAULT_ORG_ID
from app.db.session import get_db
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/organizations", tags=["organizations"])


async def _get_org_or_404(db: AsyncSession, org_id: UUID) -> Organization:
    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if org is None or org.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    rows = await db.execute(
        select(Organization).where(Organization.deleted_at.is_(None)).order_by(Organization.name)
    )
    return list(rows.scalars().all())


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    org = Organization(
        name=data.name, slug=data.slug, plan=data.plan, description=data.description
    )
    db.add(org)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="An organization with that slug already exists"
        ) from None
    await db.refresh(org)
    await audit_log(
        db, admin.id, "organization.create", "organization", str(org.id),
        {"slug": org.slug}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return org


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    return await _get_org_or_404(db, org_id)


@router.put("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: UUID,
    data: OrganizationUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    org = await _get_org_or_404(db, org_id)
    if data.name is not None:
        org.name = data.name
    if data.plan is not None:
        org.plan = data.plan
    if data.description is not None:
        org.description = data.description
    if data.suspended is not None:
        if org.id == DEFAULT_ORG_ID and data.suspended:
            raise HTTPException(status_code=400, detail="The default organization cannot be suspended")
        org.suspended_at = datetime.now(UTC) if data.suspended else None
    await db.commit()
    await db.refresh(org)
    await audit_log(
        db, admin.id, "organization.update", "organization", str(org.id),
        {"suspended": data.suspended}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    if org_id == DEFAULT_ORG_ID:
        raise HTTPException(status_code=400, detail="The default organization cannot be deleted")
    org = await _get_org_or_404(db, org_id)
    # Soft delete: keep the row (and its tenant data) but mark it gone.
    org.deleted_at = datetime.now(UTC)
    await audit_log(
        db, admin.id, "organization.delete", "organization", str(org.id),
        {"slug": org.slug}, ip_address=get_client_ip(request),
    )
    await db.commit()
