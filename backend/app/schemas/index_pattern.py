from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, field_validator


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
    # Detection mode: 'push' (real-time) or 'pull' (scheduled queries)
    mode: str = "push"
    poll_interval_minutes: int = 5
    # Timestamp field for pull mode time filtering (must be a date/timestamp field in the index)
    timestamp_field: str = "@timestamp"

    @field_validator("poll_interval_minutes")
    @classmethod
    def validate_poll_interval(cls, v: int) -> int:
        if v < 1 or v > 1440:
            raise ValueError("poll_interval_minutes must be between 1 and 1440 (24 hours)")
        return v


class IndexPatternCreate(IndexPatternBase):
    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("push", "pull"):
            raise ValueError("mode must be 'push' or 'pull'")
        return v


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
    # Detection mode
    mode: str | None = None
    poll_interval_minutes: int | None = None
    timestamp_field: str | None = None
    # IOC Detection (Push Mode)
    ioc_detection_enabled: bool | None = None
    ioc_field_mappings: dict[str, list[str]] | None = None
    # For audit logging
    change_reason: str | None = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in ("push", "pull"):
            raise ValueError("mode must be 'push' or 'pull'")
        return v

    @field_validator("poll_interval_minutes")
    @classmethod
    def validate_poll_interval(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 1440):
            raise ValueError("poll_interval_minutes must be between 1 and 1440 (24 hours)")
        return v


class IndexPatternResponse(IndexPatternBase):
    id: UUID
    auth_token: str
    mode: str
    poll_interval_minutes: int
    timestamp_field: str
    # IOC Detection
    ioc_detection_enabled: bool = False
    ioc_field_mappings: dict[str, list[str]] | None = None
    created_at: datetime
    updated_at: datetime
    last_edited_by: str | None = None  # Email of user who last edited

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
