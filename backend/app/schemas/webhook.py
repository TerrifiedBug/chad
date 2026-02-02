"""Webhook schemas for API request/response validation."""

import re
from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, HttpUrl, field_validator

# Valid HTTP header name pattern (RFC 7230)
# Must be a token: 1*tchar where tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
HTTP_HEADER_NAME_PATTERN = re.compile(r'^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+$')


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

    @field_validator('header_name')
    @classmethod
    def validate_header_name(cls, v: str | None) -> str | None:
        """Validate header name follows HTTP header naming rules."""
        if v is None or v == '':
            return None
        if not HTTP_HEADER_NAME_PATTERN.match(v):
            raise ValueError('Invalid HTTP header name. Must contain only alphanumeric characters and !#$%&\'*+-.^_`|~')
        if len(v) > 100:
            raise ValueError('Header name must be 100 characters or less')
        return v


class WebhookUpdate(BaseModel):
    """Schema for updating an existing webhook."""

    name: str | None = None
    url: HttpUrl | None = None
    header_name: str | None = None
    header_value: str | None = None
    provider: WebhookProvider | None = None
    enabled: bool | None = None

    @field_validator('header_name')
    @classmethod
    def validate_header_name(cls, v: str | None) -> str | None:
        """Validate header name follows HTTP header naming rules."""
        if v is None or v == '':
            return None
        if not HTTP_HEADER_NAME_PATTERN.match(v):
            raise ValueError('Invalid HTTP header name. Must contain only alphanumeric characters and !#$%&\'*+-.^_`|~')
        if len(v) > 100:
            raise ValueError('Header name must be 100 characters or less')
        return v


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
