from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel


class TIIndicatorType(str, Enum):
    """Types of indicators for TI enrichment."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class TIFieldConfig(BaseModel):
    """Configuration for a single field to enrich with TI."""

    field: str  # Field path like "source.ip"
    type: TIIndicatorType  # Explicit indicator type


class TISourceConfig(BaseModel):
    """Configuration for a single TI source on an index pattern."""

    enabled: bool = False
    fields: list[TIFieldConfig] = []


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
    # IP allowlist for log shipping (None = allow all)
    allowed_ips: list[str] | None = None
    # Rate limiting for log shipping
    rate_limit_enabled: bool = False
    rate_limit_requests_per_minute: int | None = None
    rate_limit_events_per_minute: int | None = None


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
    # IP allowlist for log shipping (None = allow all, [] = clear allowlist)
    allowed_ips: list[str] | None = None
    # Rate limiting for log shipping
    rate_limit_enabled: bool | None = None
    rate_limit_requests_per_minute: int | None = None
    rate_limit_events_per_minute: int | None = None


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
