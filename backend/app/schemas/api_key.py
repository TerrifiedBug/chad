from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class APIKeyCreate(BaseModel):
    name: str
    description: str | None = None
    expires_at: datetime | None = None


class APIKeyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None


class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    key_prefix: str
    user_id: UUID
    expires_at: datetime | None
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreateResponse(APIKeyResponse):
    """Response when creating a new API key - includes the full key (only shown once)."""
    key: str  # The full API key, only returned on creation
