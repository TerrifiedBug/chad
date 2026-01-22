from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID | None
    user_email: str | None = None
    action: str
    resource_type: str
    resource_id: str | None
    details: dict | None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int
    limit: int
    offset: int
