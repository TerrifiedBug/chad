"""Alert comment schemas for API requests and responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class AlertCommentCreate(BaseModel):
    """Schema for creating an alert comment."""

    content: str = Field(..., min_length=1, max_length=10000)


class AlertCommentUpdate(BaseModel):
    """Schema for updating an alert comment."""

    content: str = Field(..., min_length=1, max_length=10000)


class AlertCommentResponse(BaseModel):
    """Schema for alert comment response."""

    id: UUID
    alert_id: str
    user_id: UUID
    username: str
    content: str
    created_at: datetime
    updated_at: datetime | None = None
    is_deleted: bool = False

    model_config = {"from_attributes": True}
