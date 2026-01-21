from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client, require_admin
from app.db.session import get_db
from app.models.index_pattern import IndexPattern
from app.models.user import User
from app.schemas.index_pattern import (
    IndexPatternCreate,
    IndexPatternResponse,
    IndexPatternUpdate,
    IndexPatternValidateRequest,
    IndexPatternValidateResponse,
)
from app.services.opensearch import validate_index_pattern

router = APIRouter(prefix="/index-patterns", tags=["index-patterns"])


@router.get("", response_model=list[IndexPatternResponse])
async def list_index_patterns(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(IndexPattern))
    return result.scalars().all()


@router.post("", response_model=IndexPatternResponse, status_code=status.HTTP_201_CREATED)
async def create_index_pattern(
    pattern_data: IndexPatternCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    # Check for duplicate name
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.name == pattern_data.name)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Index pattern with this name already exists",
        )

    pattern = IndexPattern(**pattern_data.model_dump())
    db.add(pattern)
    await db.commit()
    await db.refresh(pattern)
    return pattern


@router.get("/{pattern_id}", response_model=IndexPatternResponse)
async def get_index_pattern(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(IndexPattern).where(IndexPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Index pattern not found",
        )
    return pattern


@router.patch("/{pattern_id}", response_model=IndexPatternResponse)
async def update_index_pattern(
    pattern_id: UUID,
    pattern_data: IndexPatternUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    result = await db.execute(select(IndexPattern).where(IndexPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Index pattern not found",
        )

    update_data = pattern_data.model_dump(exclude_unset=True)

    # Check for duplicate name if name is being updated
    if "name" in update_data:
        existing = await db.execute(
            select(IndexPattern).where(
                IndexPattern.name == update_data["name"],
                IndexPattern.id != pattern_id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Index pattern with this name already exists",
            )

    for field, value in update_data.items():
        setattr(pattern, field, value)

    await db.commit()
    await db.refresh(pattern)
    return pattern


@router.delete("/{pattern_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_index_pattern(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    result = await db.execute(select(IndexPattern).where(IndexPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Index pattern not found",
        )

    await db.delete(pattern)
    await db.commit()


@router.post("/validate", response_model=IndexPatternValidateResponse)
async def validate_pattern(
    request: IndexPatternValidateRequest,
    opensearch: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Validate an index pattern exists in OpenSearch.

    Returns info about matching indices and sample fields.
    """
    result = validate_index_pattern(opensearch, request.pattern)

    return IndexPatternValidateResponse(
        valid=result["valid"],
        indices=result.get("indices", []),
        total_docs=result.get("total_docs", 0),
        sample_fields=result.get("sample_fields", []),
        error=result.get("error"),
    )
