"""Webhook schemas for API request/response validation."""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, HttpUrl


class WebhookProvider(str, Enum):
    """Webhook provider types for payload formatting."""

    GENERIC = "generic"
    DISCORD = "discord"
    SLACK = "slack"


class WebhookCreate(BaseModel):
    """Schema for creating a new webhook."""

    name: str
    url: HttpUrl
    header_name: str | None = None
    header_value: str | None = None
    provider: WebhookProvider = WebhookProvider.GENERIC
    enabled: bool = True


class WebhookUpdate(BaseModel):
    """Schema for updating an existing webhook."""

    name: str | None = None
    url: HttpUrl | None = None
    header_name: str | None = None
    header_value: str | None = None
    provider: WebhookProvider | None = None
    enabled: bool | None = None


class WebhookResponse(BaseModel):
    """Schema for webhook API responses."""

    id: UUID
    name: str
    url: str
    has_auth: bool  # Don't expose actual header value
    header_name: str | None = None  # Expose header name for UI display
    provider: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WebhookTestResponse(BaseModel):
    """Schema for webhook test result."""

    success: bool
    status_code: int | None = None
    error: str | None = None
