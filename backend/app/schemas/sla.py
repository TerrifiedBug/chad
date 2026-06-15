"""Pydantic schemas for the alert SLA policy and teammate assignment."""

from uuid import UUID

from pydantic import BaseModel, Field


class SlaTargets(BaseModel):
    critical: int = Field(default=60, ge=0)
    high: int = Field(default=240, ge=0)
    medium: int = Field(default=1440, ge=0)
    low: int = Field(default=4320, ge=0)
    informational: int = Field(default=0, ge=0)


class SlaPolicyResponse(BaseModel):
    enabled: bool
    targets_minutes: SlaTargets


class SlaPolicyUpdate(BaseModel):
    enabled: bool
    targets_minutes: SlaTargets


class AssignAlertRequest(BaseModel):
    """Body for POST /alerts/{id}/assign.

    Omit ``assignee_id`` to self-assign (backward compatible). Provide it to
    assign the alert to a teammate.
    """

    assignee_id: UUID | None = None
