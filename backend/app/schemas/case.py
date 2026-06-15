"""Pydantic schemas for case management."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

CASE_STATUSES = {"open", "investigating", "contained", "closed"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str | None = None
    severity: str = Field(default="medium")
    owner_id: UUID | None = None
    tags: list[str] | None = None
    # Optionally seed the case with these alert ids on creation.
    alert_ids: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = None
    severity: str | None = None
    tags: list[str] | None = None


class CaseStatusUpdate(BaseModel):
    status: str
    note: str | None = None


class CaseAssignRequest(BaseModel):
    owner_id: UUID | None = None  # None unassigns


class CaseAlertAdd(BaseModel):
    alert_ids: list[str] = Field(min_length=1)


class CaseCommentCreate(BaseModel):
    content: str = Field(min_length=1, max_length=10000)


class CaseAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: str
    alert_title: str | None = None
    alert_severity: str | None = None
    added_by: UUID | None = None
    added_at: datetime


class CaseEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_type: str
    actor_id: UUID | None = None
    actor_email: str | None = None
    message: str
    event_metadata: dict[str, Any] | None = None
    created_at: datetime


class CaseCommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    content: str
    user_id: UUID
    user_email: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    number: int
    title: str
    description: str | None = None
    status: str
    severity: str
    owner_id: UUID | None = None
    owner_email: str | None = None
    team_id: UUID | None = None
    created_by: UUID | None = None
    sla_due_at: datetime | None = None
    sla_breached: bool = False
    closed_at: datetime | None = None
    tags: list[str] | None = None
    alert_count: int = 0
    created_at: datetime
    updated_at: datetime


class CaseDetailResponse(CaseResponse):
    alerts: list[CaseAlertResponse] = Field(default_factory=list)
    events: list[CaseEventResponse] = Field(default_factory=list)
    comments: list[CaseCommentResponse] = Field(default_factory=list)


class CaseListResponse(BaseModel):
    cases: list[CaseResponse]
    total: int
