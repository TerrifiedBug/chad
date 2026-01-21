from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.rule import RuleStatus
from app.schemas.index_pattern import IndexPatternResponse


class RuleBase(BaseModel):
    title: str
    description: str | None = None
    yaml_content: str
    severity: str = "medium"
    index_pattern_id: UUID


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    yaml_content: str | None = None
    severity: str | None = None
    status: RuleStatus | None = None
    index_pattern_id: UUID | None = None


class RuleVersionResponse(BaseModel):
    id: UUID
    version_number: int
    yaml_content: str
    created_at: datetime

    class Config:
        from_attributes = True


class RuleResponse(RuleBase):
    id: UUID
    status: RuleStatus
    snooze_until: datetime | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RuleDetailResponse(RuleResponse):
    index_pattern: IndexPatternResponse
    versions: list[RuleVersionResponse] = []


# Validation schemas
class RuleValidateRequest(BaseModel):
    yaml_content: str
    index_pattern_id: UUID | None = None  # Optional - validates syntax without field check


class ValidationErrorItem(BaseModel):
    type: str  # "syntax", "schema", "field"
    message: str
    line: int | None = None
    field: str | None = None


class RuleValidateResponse(BaseModel):
    valid: bool
    errors: list[ValidationErrorItem] = []
    opensearch_query: dict | None = None
    fields: list[str] = []


# Sample log testing schemas
class RuleTestRequest(BaseModel):
    yaml_content: str
    sample_logs: list[dict]


class LogMatchResult(BaseModel):
    log_index: int
    matched: bool


class RuleTestResponse(BaseModel):
    matches: list[LogMatchResult]
    opensearch_query: dict | None = None
    errors: list[ValidationErrorItem] = []
