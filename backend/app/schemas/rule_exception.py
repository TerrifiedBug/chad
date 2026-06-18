"""Schemas for rule exception API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.rule_exception import ExceptionOperator


class RuleExceptionCreate(BaseModel):
    field: str
    operator: ExceptionOperator = ExceptionOperator.EQUALS
    value: str
    reason: str | None = None
    change_reason: str = Field(..., min_length=1, max_length=10000)
    # Optional group_id - if not provided, a new group is created
    # If provided, this exception is added to an existing group (AND logic)
    group_id: UUID | None = None
    # If created from an alert, auto-mark alert as false positive
    alert_id: str | None = None


class RuleExceptionUpdate(BaseModel):
    field: str | None = None
    operator: ExceptionOperator | None = None
    value: str | None = None
    reason: str | None = None
    is_active: bool | None = None
    change_reason: str = Field(..., min_length=1, max_length=10000)


class RuleExceptionResponse(BaseModel):
    id: UUID
    rule_id: UUID
    group_id: UUID
    field: str
    operator: ExceptionOperator
    value: str
    reason: str | None
    is_active: bool
    created_by: UUID
    created_at: datetime
    warning: str | None = None  # Overlap warning if applicable

    class Config:
        from_attributes = True


class ExceptionPreviewClause(BaseModel):
    """A single candidate exception condition to preview."""

    field: str = Field(..., min_length=1)
    operator: ExceptionOperator = ExceptionOperator.EQUALS
    value: str


class ExceptionPreviewRequest(BaseModel):
    """Preview how many past events a candidate exception would suppress."""

    start_date: datetime
    end_date: datetime
    limit: int = Field(default=500, ge=1, le=1000)
    clauses: list[ExceptionPreviewClause] = Field(..., min_length=1)


class ExceptionPreviewResponse(BaseModel):
    """Suppression delta over the selected time range."""

    total_matches: int
    suppressed: int
    remaining: int
    error: str | None = None
