"""Alert schemas for API requests and responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


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


class AlertListResponse(BaseModel):
    total: int
    alerts: list[AlertResponse]


class AlertStatusUpdate(BaseModel):
    status: str  # new, acknowledged, resolved, false_positive


class AlertCountsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    last_24h: int
