"""Schemas for bulk operations."""

from pydantic import BaseModel, Field


class BulkOperationRequest(BaseModel):
    """Request body for bulk operations on rules."""

    rule_ids: list[str]
    change_reason: str = Field(..., min_length=1, max_length=10000)


class BulkOperationResult(BaseModel):
    """Result of a bulk operation."""

    success: list[str]
    failed: list[dict]  # {"id": str, "error": str}
