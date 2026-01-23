"""Webhook schemas for API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, HttpUrl


class WebhookCreate(BaseModel):
    """Schema for creating a new webhook."""

    name: str
    url: HttpUrl
    auth_header: str | None = None
    enabled: bool = True


class WebhookUpdate(BaseModel):
    """Schema for updating an existing webhook."""

    name: str | None = None
    url: HttpUrl | None = None
    auth_header: str | None = None
    enabled: bool | None = None


class WebhookResponse(BaseModel):
    """Schema for webhook API responses."""

    id: UUID
    name: str
    url: str
    has_auth: bool  # Don't expose actual auth header
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
