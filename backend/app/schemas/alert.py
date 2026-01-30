"""Alert schemas for API requests and responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ExceptionCreatedInfo(BaseModel):
    """Info about an exception that was created from this alert."""

    exception_id: str
    field: str
    value: str
    match_type: str
    created_at: str


class AlertResponse(BaseModel):
    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    tags: list[str]
    status: str
    log_document: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    # Ownership fields
    owner_id: str | None = None
    owner_username: str | None = None
    owned_at: datetime | None = None
    # Exception tracking
    exception_created: ExceptionCreatedInfo | None = None
    # TI enrichment (optional, may be large)
    ti_enrichment: dict[str, Any] | None = None


class AlertListResponse(BaseModel):
    total: int
    alerts: list[AlertResponse]


class AlertCluster(BaseModel):
    """A cluster of related alerts."""

    representative: AlertResponse
    count: int
    alert_ids: list[str]
    time_range: tuple[str | None, str | None]


class ClusteredAlertListResponse(BaseModel):
    """Response for alerts list when clustering is enabled."""

    total: int
    total_clusters: int
    clusters: list[AlertCluster]


class AlertStatusUpdate(BaseModel):
    status: str  # new, acknowledged, resolved, false_positive


class AlertCountsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    last_24h: int
