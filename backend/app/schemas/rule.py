from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.core.sanitization import sanitize_html
from app.models.rule import RuleSource, RuleStatus
from app.schemas.index_pattern import IndexPatternResponse


class RuleBase(BaseModel):
    title: str
    description: str | None = None
    yaml_content: str
    severity: str = "medium"
    index_pattern_id: UUID

    @field_validator('description')
    @classmethod
    def sanitize_description(cls, v: str | None) -> str | None:
        """Sanitize HTML in description to prevent XSS."""
        if v is None:
            return None
        return sanitize_html(v, allow_tags=['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'code', 'pre'])


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
    change_reason: str | None = None
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
    change_reason: str
    changed_by: UUID

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
    has_open_request: bool = False  # True if an OPEN (pending) DeploymentRequest exists
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
    index_pattern_id: UUID | None = None


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
    percolator_index: str | None = None  # None for pull mode (no percolator)
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


# Deploy preview schemas (consolidates eligibility + validate + current/proposed
# diff into a single read-only call for the DeployDialog).
class DeployPreviewValidation(BaseModel):
    """Translation/validation outcome for the rule's current YAML."""

    success: bool
    errors: list[ValidationErrorItem] = []


class DeployPreviewEligibility(BaseModel):
    """Field-mapping eligibility for this one rule (reuses the bulk logic)."""

    eligible: bool
    reason: str | None = None
    unmapped_fields: list[str] = []


class DeployPreviewResponse(BaseModel):
    """Read-only deploy preview for a single rule. Never mutates anything."""

    rule_id: UUID
    # The DSL currently live in the percolator (inner query), or null when the
    # rule is undeployed / pull-mode / not found in the percolator.
    current_deployed_query: dict | None = None
    # Freshly translated current YAML with mappings applied (inner query).
    proposed_query: dict | None = None
    validation: DeployPreviewValidation
    eligibility: DeployPreviewEligibility
    needs_redeploy: bool = False
    deployed_version: int | None = None
    current_version: int = 1
    # Optional historical dry-run summary; kept null (lazy) to keep this cheap.
    dry_run: dict | None = None


# Historical testing schemas
class HistoricalTestRequest(BaseModel):
    """Request body for historical rule testing."""

    start_date: datetime
    end_date: datetime
    limit: int = Field(default=500, ge=1, le=1000)


class HistoricalTestMatch(BaseModel):
    """A single match from historical testing."""

    _id: str
    _index: str
    _source: dict[str, Any]


class HistoricalTestResponse(BaseModel):
    """Response for historical rule testing."""

    total_scanned: int
    total_matches: int
    matches: list[dict[str, Any]]
    truncated: bool
    query_executed: dict[str, Any] | None = None
    error: str | None = None
