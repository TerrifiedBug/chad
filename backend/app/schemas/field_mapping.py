"""Schemas for field mapping API."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.field_mapping import MappingOrigin


class FieldMappingCreate(BaseModel):
    sigma_field: str
    target_field: str
    index_pattern_id: UUID | None = None
    origin: MappingOrigin = MappingOrigin.MANUAL
    confidence: float | None = None


class FieldMappingUpdate(BaseModel):
    target_field: str | None = None
    origin: MappingOrigin | None = None
    confidence: float | None = None


class FieldMappingResponse(BaseModel):
    id: UUID
    sigma_field: str
    target_field: str
    index_pattern_id: UUID | None
    origin: MappingOrigin
    confidence: float | None
    created_by: UUID
    created_at: datetime
    version: int = 1

    class Config:
        from_attributes = True


class AISuggestRequest(BaseModel):
    index_pattern_id: UUID
    sigma_fields: list[str]
    logsource: dict | None = None


class AISuggestionResponse(BaseModel):
    sigma_field: str
    target_field: str | None
    confidence: float
    reason: str
