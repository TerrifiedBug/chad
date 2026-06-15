"""Schemas for dual-control deployment approval requests."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class DeploymentRequestCreate(BaseModel):
    """Maker request to deploy one or more rules (batch)."""

    rule_ids: list[UUID] = Field(..., min_length=1)
    change_reason: str = Field(..., min_length=1, max_length=10000)
    # Optional quorum override (default 1). Capped server-side.
    required_approvals: int | None = Field(default=None, ge=1, le=10)


class DeploymentRequestApprovalInfo(BaseModel):
    """One recorded approval toward the quorum."""

    approver_id: UUID
    approver_email: str | None
    note: str | None
    created_at: datetime


class DeploymentRequestReject(BaseModel):
    """Checker rejection with a required note."""

    review_note: str = Field(..., min_length=1, max_length=10000)


class DeploymentRequestItemResponse(BaseModel):
    """Summary view of a single pinned item."""

    id: UUID
    kind: str
    rule_id: UUID | None
    correlation_rule_id: UUID | None
    rule_title: str | None
    version_number: int
    apply_status: str | None
    apply_error: str | None


class DeploymentRequestItemDetail(DeploymentRequestItemResponse):
    """Item view with the YAML needed to render a proposed-vs-deployed diff."""

    proposed_yaml: str | None
    deployed_yaml: str | None
    is_stale: bool


class DeploymentRequestResponse(BaseModel):
    """List/summary view of a request."""

    id: UUID
    status: str
    requested_by: UUID
    requester_email: str | None
    reviewed_by: UUID | None
    reviewer_email: str | None
    change_reason: str
    review_note: str | None
    team_id: UUID | None
    created_at: datetime
    reviewed_at: datetime | None
    applied_at: datetime | None
    item_count: int
    rule_titles: list[str]
    age_seconds: float
    # Maker-checker hardening (I3): quorum progress + approval SLA.
    required_approvals: int = 1
    approvals_count: int = 0
    approval_deadline: datetime | None = None
    is_overdue: bool = False


class DeploymentRequestDetailResponse(DeploymentRequestResponse):
    """Detail view with per-item diff data."""

    items: list[DeploymentRequestItemDetail]
    approvals: list[DeploymentRequestApprovalInfo] = Field(default_factory=list)


class DeploymentRequestStats(BaseModel):
    """KPI strip aggregates."""

    pending: int
    approved: int
    applied: int
    rejected: int
    cancelled: int
    stale: int
    failed: int
    avg_review_seconds: float | None
