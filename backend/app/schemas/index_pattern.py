from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class TISourceConfig(BaseModel):
    """Configuration for a single TI source on an index pattern."""

    enabled: bool = False
    fields: list[str] = []


class IndexPatternBase(BaseModel):
    name: str
    pattern: str
    percolator_index: str
    description: str | None = None
    health_no_data_minutes: int | None = None
    health_error_rate_percent: float | None = None
    health_latency_ms: int | None = None
    health_alerting_enabled: bool = True
    geoip_fields: list[str] = []
    ti_config: dict[str, TISourceConfig] | None = None


class IndexPatternCreate(IndexPatternBase):
    pass


class IndexPatternUpdate(BaseModel):
    name: str | None = None
    pattern: str | None = None
    percolator_index: str | None = None
    description: str | None = None
    health_no_data_minutes: int | None = None
    health_error_rate_percent: float | None = None
    health_latency_ms: int | None = None
    health_alerting_enabled: bool | None = None
    geoip_fields: list[str] | None = None
    ti_config: dict[str, TISourceConfig] | None = None


class IndexPatternResponse(IndexPatternBase):
    id: UUID
    auth_token: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IndexPatternTokenResponse(BaseModel):
    """Response for token regeneration."""
    auth_token: str


# Validation schemas
class IndexPatternValidateRequest(BaseModel):
    pattern: str


class IndexPatternValidateResponse(BaseModel):
    valid: bool
    indices: list[str] = []
    total_docs: int = 0
    sample_fields: list[str] = []
    error: str | None = None
