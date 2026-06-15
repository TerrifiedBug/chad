"""Pydantic schemas for scheduled reports."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

REPORT_TYPES = {"coverage", "detection_kpis", "rule_health", "compliance"}
CADENCES = {"daily", "weekly", "monthly"}
FRAMEWORKS = {"pci_dss", "soc2", "iso_27001", "dora"}


class ReportScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    report_type: str = "coverage"
    cadence: str = "weekly"
    framework: str | None = None
    delivery_type: str = "webhook"
    delivery_target: str | None = None
    delivery_header_name: str | None = None
    delivery_header_value: str | None = None  # write-only
    enabled: bool = True


class ReportScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    cadence: str | None = None
    framework: str | None = None
    delivery_target: str | None = None
    delivery_header_name: str | None = None
    delivery_header_value: str | None = None
    enabled: bool | None = None


class ReportScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    report_type: str
    cadence: str
    framework: str | None = None
    delivery_type: str
    delivery_target: str | None = None
    delivery_header_name: str | None = None
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
