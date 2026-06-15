"""Pydantic schemas for organization (tenant) management."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.org_constants import ORG_SLUG_PATTERN


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(pattern=ORG_SLUG_PATTERN)
    plan: str = Field(default="standard", max_length=50)
    description: str | None = None


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    plan: str | None = Field(default=None, max_length=50)
    description: str | None = None
    # Lifecycle toggles (suspend/restore). None = leave unchanged.
    suspended: bool | None = None


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    plan: str
    suspended_at: datetime | None = None
    deleted_at: datetime | None = None
    description: str | None = None
    created_at: datetime
    updated_at: datetime
