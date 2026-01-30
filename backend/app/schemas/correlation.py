"""Schemas for correlation rules."""

from datetime import datetime

from pydantic import BaseModel, Field


class CorrelationRuleBase(BaseModel):
    """Base schema for correlation rules."""

    name: str = Field(..., min_length=1, max_length=255)
    rule_a_id: str
    rule_b_id: str
    entity_field: str = Field(..., max_length=100)
    entity_field_type: str = Field(default="sigma", pattern="^(sigma|direct)$")
    time_window_minutes: int = Field(..., ge=1, le=1440)
    severity: str = Field(..., pattern="^(critical|high|medium|low|informational)$")


class CorrelationRuleCreate(CorrelationRuleBase):
    """Schema for creating a correlation rule."""

    change_reason: str = Field(..., min_length=1, max_length=10000)


class CorrelationRuleUpdate(BaseModel):
    """Schema for updating a correlation rule."""

    name: str | None = Field(None, min_length=1, max_length=255)
    entity_field: str | None = Field(None, max_length=100)
    entity_field_type: str | None = Field(None, pattern="^(sigma|direct)$")
    time_window_minutes: int | None = Field(None, ge=1, le=1440)
    severity: str | None = Field(None, pattern="^(critical|high|medium|low|informational)$")
    change_reason: str | None = None


class CorrelationRuleResponse(CorrelationRuleBase):
    """Schema for correlation rule response."""

    id: str
    created_at: datetime
    updated_at: datetime
    created_by: str | None
    last_edited_by: str | None = None

    # Deployment tracking
    deployed_at: datetime | None = None
    deployed_version: int | None = None
    current_version: int = 1
    needs_redeploy: bool = False

    # Snooze fields
    snooze_until: datetime | None = None
    snooze_indefinite: bool = False

    # Include related rule info
    rule_a_title: str | None = None
    rule_b_title: str | None = None

    # Linked rule deployment status (for determining if correlation can be deployed)
    rule_a_deployed: bool = True
    rule_b_deployed: bool = True

    class Config:
        from_attributes = True


class CorrelationRuleListResponse(BaseModel):
    """Schema for list of correlation rules."""

    correlation_rules: list[CorrelationRuleResponse]
    total: int


class CorrelationRuleDeployRequest(BaseModel):
    """Schema for deploying a correlation rule."""

    change_reason: str = Field(..., min_length=1, max_length=10000)


class CorrelationRuleVersionResponse(BaseModel):
    """Schema for correlation rule version history."""

    id: str
    version_number: int
    name: str
    rule_a_id: str
    rule_b_id: str
    entity_field: str
    entity_field_type: str = "sigma"
    time_window_minutes: int
    severity: str
    changed_by: str
    changed_by_email: str | None = None
    change_reason: str
    created_at: datetime

    class Config:
        from_attributes = True


class CorrelationRuleCommentCreate(BaseModel):
    """Schema for creating a comment on a correlation rule."""

    content: str = Field(..., min_length=1, max_length=10000)


class CorrelationRuleCommentResponse(BaseModel):
    """Schema for correlation rule comment response."""

    id: str
    correlation_rule_id: str
    user_id: str | None
    user_email: str | None
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


class CorrelationActivityItem(BaseModel):
    """Activity timeline item for a correlation rule."""

    type: str  # 'version', 'deploy', 'undeploy', 'comment'
    timestamp: datetime
    user_email: str | None
    data: dict


class CorrelationRuleRollbackResponse(BaseModel):
    """Response schema for correlation rule rollback."""

    success: bool
    new_version_number: int
    rolled_back_from: int


class CorrelationSnoozeRequest(BaseModel):
    """Schema for snoozing a correlation rule."""

    hours: int | None = Field(default=None, ge=1, le=168)  # None allowed if indefinite
    indefinite: bool = False
    change_reason: str = Field(..., min_length=1, max_length=10000)


class BulkCorrelationSnoozeRequest(BaseModel):
    """Request body for bulk snooze operations on correlation rules."""

    rule_ids: list[str]
    hours: int | None = Field(default=None, ge=1, le=168)  # None allowed if indefinite
    indefinite: bool = False
    change_reason: str = Field(..., min_length=1, max_length=10000)


class CommonLogFieldsResponse(BaseModel):
    """Response schema for common log fields between two rules."""

    common_fields: list[str]  # Fields with same name in both index patterns
    mapped_fields: list[dict]  # Fields bridged via field mappings
