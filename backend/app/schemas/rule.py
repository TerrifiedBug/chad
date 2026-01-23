from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.rule import RuleSource, RuleStatus
from app.schemas.index_pattern import IndexPatternResponse


class RuleBase(BaseModel):
    title: str
    description: str | None = None
    yaml_content: str
    severity: str = "medium"
    index_pattern_id: UUID


class RuleCreate(RuleBase):
    status: RuleStatus = RuleStatus.UNDEPLOYED
    # Threshold alerting
    threshold_enabled: bool = False
    threshold_count: int | None = None
    threshold_window_minutes: int | None = None
    threshold_group_by: str | None = None


class RuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    yaml_content: str | None = None
    severity: str | None = None
    status: RuleStatus | None = None
    index_pattern_id: UUID | None = None
    # Threshold alerting
    threshold_enabled: bool | None = None
    threshold_count: int | None = None
    threshold_window_minutes: int | None = None
    threshold_group_by: str | None = None


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
    snooze_indefinite: bool = False
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    deployed_at: datetime | None = None
    deployed_version: int | None = None
    current_version: int = 1  # Latest version number
    needs_redeploy: bool = False  # True if deployed but out of date
    last_edited_by: str | None = None  # Email of user who last edited
    source: RuleSource = RuleSource.USER
    sigmahq_path: str | None = None
    # Threshold alerting
    threshold_enabled: bool = False
    threshold_count: int | None = None
    threshold_window_minutes: int | None = None
    threshold_group_by: str | None = None

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


class FieldMappingInfo(BaseModel):
    sigma_field: str
    target_field: str | None  # None if unmapped


class RuleValidateResponse(BaseModel):
    valid: bool
    errors: list[ValidationErrorItem] = []
    opensearch_query: dict | None = None
    fields: list[str] = []
    field_mappings: list[FieldMappingInfo] = []


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


# Deployment schemas
class RuleDeployResponse(BaseModel):
    success: bool
    rule_id: UUID
    percolator_index: str
    deployed_version: int
    deployed_at: datetime


class RuleUndeployResponse(BaseModel):
    success: bool
    message: str


class RuleRollbackResponse(BaseModel):
    success: bool
    new_version_number: int
    rolled_back_from: int
    yaml_content: str


class UnmappedFieldsError(BaseModel):
    """Error response when deployment fails due to unmapped fields."""

    error: str = "unmapped_fields"
    message: str
    unmapped_fields: list[str]
    index_pattern_id: UUID
