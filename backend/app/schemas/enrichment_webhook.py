"""Pydantic schemas for enrichment webhook API."""

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")


class EnrichmentWebhookBase(BaseModel):
    """Base schema for enrichment webhook."""

    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=2048)
    namespace: str = Field(..., min_length=1, max_length=64)
    method: str = Field(default="POST", pattern="^(GET|POST)$")
    header_name: str | None = Field(default="Authorization", max_length=255)
    header_value: str | None = Field(default=None)  # Plaintext on input, encrypted on store
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_concurrent_calls: int = Field(default=5, ge=1, le=50)
    cache_ttl_seconds: int = Field(default=0, ge=0, le=86400)  # 0 = no cache, max 24h
    is_active: bool = Field(default=True)
    include_ioc_alerts: bool = Field(default=False)

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, v: str) -> str:
        if not NAMESPACE_PATTERN.match(v):
            raise ValueError(
                "Namespace must start with a letter, contain only "
                "alphanumeric characters and underscores"
            )
        return v.lower()

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class EnrichmentWebhookCreate(EnrichmentWebhookBase):
    """Schema for creating an enrichment webhook."""

    pass


class EnrichmentWebhookUpdate(BaseModel):
    """Schema for updating an enrichment webhook."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    method: str | None = Field(default=None, pattern="^(GET|POST)$")
    header_name: str | None = None
    header_value: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=30)
    max_concurrent_calls: int | None = Field(default=None, ge=1, le=50)
    cache_ttl_seconds: int | None = Field(default=None, ge=0, le=86400)
    is_active: bool | None = None
    include_ioc_alerts: bool | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class EnrichmentWebhookResponse(BaseModel):
    """Schema for enrichment webhook response."""

    id: UUID
    name: str
    url: str
    namespace: str
    method: str
    header_name: str | None
    has_credentials: bool  # Don't expose actual value
    timeout_seconds: int
    max_concurrent_calls: int
    cache_ttl_seconds: int
    is_active: bool
    include_ioc_alerts: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EnrichmentWebhookTestRequest(BaseModel):
    """Schema for testing an enrichment webhook."""

    url: str
    method: str = "POST"
    header_name: str | None = None
    header_value: str | None = None
    timeout_seconds: int = Field(default=5, ge=1, le=30)


class EnrichmentWebhookTestResponse(BaseModel):
    """Schema for webhook test response."""

    success: bool
    status_code: int | None = None
    response_body: dict | None = None
    error: str | None = None
    duration_ms: int | None = None


# Index pattern enrichment config schemas
class IndexPatternEnrichmentConfig(BaseModel):
    """Config for a single webhook on an index pattern."""

    webhook_id: UUID
    field_to_send: str = Field(..., min_length=1, max_length=255)
    is_enabled: bool = True


class IndexPatternEnrichmentConfigResponse(BaseModel):
    """Response for index pattern enrichment config."""

    webhook_id: UUID
    webhook_name: str
    webhook_namespace: str
    field_to_send: str
    is_enabled: bool

    model_config = {"from_attributes": True}


class IndexPatternEnrichmentsUpdate(BaseModel):
    """Schema for updating all enrichments on an index pattern."""

    enrichments: list[IndexPatternEnrichmentConfig]
