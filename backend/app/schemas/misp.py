"""Pydantic schemas for MISP integration."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class MISPEventSummary(BaseModel):
    """Summary of a MISP event for listing."""

    id: str
    uuid: str | None = None
    info: str
    date: str
    threat_level: str
    threat_level_id: int
    ioc_count: int
    ioc_summary: dict[str, int]
    tags: list[str] = []


class MISPAttribute(BaseModel):
    """A single MISP attribute (IOC)."""

    id: str
    type: str
    value: str
    comment: str | None = None
    to_ids: bool = True
    on_warning_list: bool = False
    warning_list_name: str | None = None


class MISPEventIOCs(BaseModel):
    """IOCs from a MISP event grouped by type."""

    event_id: str
    event_info: str
    iocs_by_type: dict[str, list[MISPAttribute]]


class MISPSearchRequest(BaseModel):
    """Request to search MISP events."""

    limit: int = Field(default=50, ge=1, le=200)
    date_from: str | None = None
    date_to: str | None = None
    threat_levels: list[int] = Field(default=[1, 2])  # High, Medium
    enforce_warninglist: bool = True
    to_ids: bool = True
    search_term: str | None = None


class MISPImportRequest(BaseModel):
    """Request to import IOCs as a Sigma rule."""

    event_id: str
    ioc_type: str
    ioc_values: list[str]
    index_pattern_id: UUID | None = None


class MISPImportResponse(BaseModel):
    """Response from rule import."""

    success: bool
    rule_id: str
    title: str
    message: str


class MISPImportedRuleInfo(BaseModel):
    """MISP origin info for a rule."""

    misp_url: str
    misp_event_id: str
    misp_event_uuid: str | None
    misp_event_info: str | None
    misp_event_date: datetime | None
    misp_event_threat_level: str | None
    ioc_type: str
    ioc_count: int
    imported_at: datetime
    last_checked_at: datetime | None
    has_updates: bool = False


class MISPConnectionStatus(BaseModel):
    """Status of MISP connection."""

    configured: bool
    connected: bool = False
    error: str | None = None
    instance_url: str | None = None
