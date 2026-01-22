"""Schemas for bulk operations."""

from pydantic import BaseModel


class BulkOperationRequest(BaseModel):
    """Request body for bulk operations on rules."""

    rule_ids: list[str]


class BulkOperationResult(BaseModel):
    """Result of a bulk operation."""

    success: list[str]
    failed: list[dict]  # {"id": str, "error": str}
