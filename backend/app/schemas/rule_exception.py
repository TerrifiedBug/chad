"""Schemas for rule exception API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.rule_exception import ExceptionOperator


class RuleExceptionCreate(BaseModel):
    field: str
    operator: ExceptionOperator = ExceptionOperator.EQUALS
    value: str
    reason: str | None = None


class RuleExceptionUpdate(BaseModel):
    field: str | None = None
    operator: ExceptionOperator | None = None
    value: str | None = None
    reason: str | None = None
    is_active: bool | None = None


class RuleExceptionResponse(BaseModel):
    id: UUID
    rule_id: UUID
    field: str
    operator: ExceptionOperator
    value: str
    reason: str | None
    is_active: bool
    created_by: UUID
    created_at: datetime

    class Config:
        from_attributes = True
