"""Pydantic schemas for saved views (filter presets)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Resource types a saved view can target. Kept in sync with the frontend list
# pages that consume saved views.
ALLOWED_RESOURCES = {"alerts", "ioc_matches", "rules", "correlation"}


class SavedViewCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    resource: str = Field(min_length=1, max_length=32)
    filters: dict[str, Any] = Field(default_factory=dict)
    is_shared: bool = False
    is_default: bool = False


class SavedViewUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    filters: dict[str, Any] | None = None
    is_shared: bool | None = None
    is_default: bool | None = None


class SavedViewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    resource: str
    owner_id: UUID
    team_id: UUID | None = None
    is_shared: bool
    is_default: bool
    filters: dict[str, Any]
    created_at: datetime
    updated_at: datetime
