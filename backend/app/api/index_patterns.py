from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client, require_admin, require_permission_dep
from app.db.session import get_db
from app.models.index_pattern import IndexPattern, generate_auth_token
from app.models.rule import Rule
from app.models.user import User
from app.schemas.index_pattern import (
    IndexPatternCreate,
    IndexPatternResponse,
    IndexPatternTokenResponse,
    IndexPatternUpdate,
    IndexPatternValidateRequest,
    IndexPatternValidateResponse,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip
from app.services.opensearch import get_index_fields, validate_index_pattern

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
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
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

    # Check for duplicate pattern
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.pattern == pattern_data.pattern)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An index pattern with this pattern already exists",
        )

    # Check for duplicate percolator_index
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.percolator_index == pattern_data.percolator_index)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An index pattern with this percolator index already exists",
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
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
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

    # Check for duplicate pattern if pattern is being updated
    if "pattern" in update_data:
        existing = await db.execute(
            select(IndexPattern).where(
                IndexPattern.pattern == update_data["pattern"],
                IndexPattern.id != pattern_id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An index pattern with this pattern already exists",
            )

    # Check for duplicate percolator_index if percolator_index is being updated
    if "percolator_index" in update_data:
        existing = await db.execute(
            select(IndexPattern).where(
                IndexPattern.percolator_index == update_data["percolator_index"],
                IndexPattern.id != pattern_id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An index pattern with this percolator index already exists",
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
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    result = await db.execute(select(IndexPattern).where(IndexPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Index pattern not found",
        )

    # Check if any rules are using this index pattern
    rule_count_result = await db.execute(
        select(func.count()).select_from(Rule).where(Rule.index_pattern_id == pattern_id)
    )
    rule_count = rule_count_result.scalar()

    if rule_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete index pattern: {rule_count} rule{'s' if rule_count != 1 else ''} {'are' if rule_count != 1 else 'is'} using this pattern. Reassign or delete the rules first.",
        )

    await db.delete(pattern)
    await db.commit()


@router.post("/{pattern_id}/regenerate-token", response_model=IndexPatternTokenResponse)
async def regenerate_auth_token(
    pattern_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """
    Regenerate the auth token for an index pattern.

    This invalidates any existing tokens and generates a new one.
    Only admins can regenerate tokens.
    """
    result = await db.execute(select(IndexPattern).where(IndexPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Index pattern not found",
        )

    # Generate new token
    pattern.auth_token = generate_auth_token()
    await db.commit()
    await db.refresh(pattern)

    # Audit log the token regeneration
    await audit_log(
        db,
        current_user.id,
        "index_pattern.regenerate_token",
        "index_pattern",
        str(pattern.id),
        {"name": pattern.name},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return IndexPatternTokenResponse(auth_token=pattern.auth_token)


@router.get("/{pattern_id}/fields", response_model=list[str])
async def get_index_pattern_fields(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    opensearch: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Get available fields from an index pattern's OpenSearch index.

    Returns a list of field names that can be used as mapping targets.
    """
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == pattern_id)
    )
    pattern = result.scalar_one_or_none()
    if pattern is None:
        raise HTTPException(status_code=404, detail="Index pattern not found")

    try:
        fields = get_index_fields(opensearch, pattern.pattern)
        return sorted(fields)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to get index fields: {e}",
        )


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
