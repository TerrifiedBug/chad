from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class IndexPatternBase(BaseModel):
    name: str
    pattern: str
    percolator_index: str
    description: str | None = None


class IndexPatternCreate(IndexPatternBase):
    pass


class IndexPatternUpdate(BaseModel):
    name: str | None = None
    pattern: str | None = None
    percolator_index: str | None = None
    description: str | None = None


class IndexPatternResponse(IndexPatternBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
