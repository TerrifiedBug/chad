"""Field mappings API endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_opensearch_client_optional
from app.models.index_pattern import IndexPattern
from app.models.user import User
from app.schemas.field_mapping import (
    AISuggestRequest,
    AISuggestionResponse,
    FieldMappingCreate,
    FieldMappingResponse,
    FieldMappingUpdate,
)
from app.services.ai_mapping import suggest_mappings
from app.services.audit import audit_log
from app.services.field_mapping import (
    create_mapping,
    delete_mapping,
    get_mappings,
    update_mapping,
)
from app.services.opensearch import get_index_fields
from app.utils.request import get_client_ip

router = APIRouter(prefix="/field-mappings", tags=["field-mappings"])


@router.get("", response_model=list[FieldMappingResponse])
async def list_mappings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    index_pattern_id: UUID | None = None,
):
    """List field mappings, optionally filtered by index pattern."""
    return await get_mappings(db, index_pattern_id)


@router.post("", response_model=FieldMappingResponse, status_code=status.HTTP_201_CREATED)
async def create_field_mapping(
    request: Request,
    data: FieldMappingCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Create a new field mapping."""
    mapping = await create_mapping(
        db,
        sigma_field=data.sigma_field,
        target_field=data.target_field,
        index_pattern_id=data.index_pattern_id,
        created_by=current_user.id,
        origin=data.origin,
        confidence=data.confidence,
    )
    await audit_log(
        db,
        current_user.id,
        "field_mapping.create",
        "field_mapping",
        str(mapping.id),
        {"sigma_field": data.sigma_field, "target_field": data.target_field},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return mapping


@router.put("/{mapping_id}", response_model=FieldMappingResponse)
async def update_field_mapping(
    mapping_id: UUID,
    request: Request,
    data: FieldMappingUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Update an existing field mapping."""
    mapping = await update_mapping(
        db,
        mapping_id,
        target_field=data.target_field,
        origin=data.origin,
        confidence=data.confidence,
    )
    if mapping is None:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await audit_log(
        db,
        current_user.id,
        "field_mapping.update",
        "field_mapping",
        str(mapping_id),
        {"changes": data.model_dump(exclude_none=True)},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return mapping


@router.delete("/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_field_mapping(
    mapping_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Delete a field mapping."""
    result = await delete_mapping(db, mapping_id)
    if not result:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await audit_log(
        db,
        current_user.id,
        "field_mapping.delete",
        "field_mapping",
        str(mapping_id),
        {},
        ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/suggest", response_model=list[AISuggestionResponse])
async def suggest_field_mappings(
    data: AISuggestRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    os_client=Depends(get_opensearch_client_optional),
):
    """Get AI suggestions for field mappings."""
    if os_client is None:
        raise HTTPException(status_code=503, detail="OpenSearch not configured")

    # Get index pattern
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == data.index_pattern_id)
    )
    index_pattern = result.scalar_one_or_none()
    if index_pattern is None:
        raise HTTPException(status_code=404, detail="Index pattern not found")

    # Get available fields from index pattern
    try:
        log_fields = list(get_index_fields(os_client, index_pattern.pattern))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Failed to get index fields: {e}")

    # Get AI suggestions
    try:
        suggestions = await suggest_mappings(
            db, data.sigma_fields, log_fields, data.logsource
        )
        return [
            AISuggestionResponse(
                sigma_field=s.sigma_field,
                target_field=s.target_field,
                confidence=s.confidence,
                reason=s.reason,
            )
            for s in suggestions
        ]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
