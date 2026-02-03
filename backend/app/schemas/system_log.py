"""
Schemas for system log API.
"""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class LogLevel(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class LogCategory(str, Enum):
    OPENSEARCH = "opensearch"
    ALERTS = "alerts"
    PULL_MODE = "pull_mode"
    INTEGRATIONS = "integrations"
    BACKGROUND = "background"


class SystemLogEntry(BaseModel):
    """Single system log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    level: str
    category: str
    service: str
    message: str
    details: dict | None = None
    created_at: datetime


class SystemLogListResponse(BaseModel):
    """Paginated system log list."""

    items: list[SystemLogEntry]
    total: int
    limit: int
    offset: int


class SystemLogStatsResponse(BaseModel):
    """System log statistics for dashboard."""

    errors_24h: int
    warnings_24h: int
    by_category: dict[str, dict[str, int]]


class SystemLogPurgeResponse(BaseModel):
    """Response for manual purge operation."""

    deleted_count: int
