"""Pydantic schemas for environments (Model B per-env deployment scopes)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    team_id: UUID | None = None
    is_default: bool = False
    require_deploy_approval: bool = False
    opensearch_index_prefix: str | None = Field(default=None, max_length=255)
    color: str | None = Field(default=None, max_length=32)


class EnvironmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    is_default: bool | None = None
    require_deploy_approval: bool | None = None
    opensearch_index_prefix: str | None = Field(default=None, max_length=255)
    color: str | None = Field(default=None, max_length=32)


class EnvironmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None = None
    team_id: UUID | None = None
    is_default: bool
    require_deploy_approval: bool
    opensearch_index_prefix: str | None = None
    color: str | None = None
    created_at: datetime
    updated_at: datetime
    # Per-env deploy aggregates (filled by the list/detail endpoints).
    rule_count: int = 0
    deployed_count: int = 0
