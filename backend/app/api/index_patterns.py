from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_opensearch_client, require_permission_dep
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
from app.services.opensearch import get_index_fields, get_time_fields, validate_index_pattern
from app.utils.request import get_client_ip

router = APIRouter(prefix="/index-patterns", tags=["index-patterns"])


@router.get("", response_model=list[IndexPatternResponse])
async def list_index_patterns(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(IndexPattern).options(selectinload(IndexPattern.updated_by))
    )
    return result.scalars().all()


@router.post("", response_model=IndexPatternResponse, status_code=status.HTTP_201_CREATED)
async def create_index_pattern(
    pattern_data: IndexPatternCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_index_config"))],
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

    # Schedule pull poll job if this is a pull mode index
    if pattern.mode == "pull":
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.schedule_pull_poll_job(
                str(pattern.id),
                pattern.name,
                pattern.poll_interval_minutes,
            )
        except Exception:
            pass  # Scheduler may not be available during tests

    return pattern


@router.get("/{pattern_id}", response_model=IndexPatternResponse)
async def get_index_pattern(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(IndexPattern)
        .where(IndexPattern.id == pattern_id)
        .options(selectinload(IndexPattern.updated_by))
    )
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
    opensearch: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_index_config"))],
):
    import logging
    from app.services.percolator import PercolatorService

    logger = logging.getLogger(__name__)

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

    # Handle mode transition: push -> pull
    # When switching to pull mode, percolator queries are no longer needed
    # (pull mode queries OpenSearch directly instead of using percolate API)
    old_mode = pattern.mode
    new_mode = update_data.get("mode")

    if new_mode == "pull" and old_mode == "push":
        try:
            percolator_service = PercolatorService(opensearch)
            deleted_count = percolator_service.undeploy_all_rules(pattern.percolator_index)
            if deleted_count > 0:
                logger.info(
                    f"Mode transition (push -> pull): Removed {deleted_count} percolator queries "
                    f"from {pattern.percolator_index}"
                )
        except Exception as e:
            logger.warning(f"Failed to cleanup percolator queries during mode transition: {e}")

    for field, value in update_data.items():
        setattr(pattern, field, value)

    # Track who made this update
    pattern.updated_by_id = current_user.id

    await db.commit()
    await db.refresh(pattern)

    # Update scheduler for pull mode changes
    try:
        from app.services.scheduler import scheduler_service

        if pattern.mode == "pull":
            # Schedule or update pull poll job
            scheduler_service.schedule_pull_poll_job(
                str(pattern.id),
                pattern.name,
                pattern.poll_interval_minutes,
            )
        elif old_mode == "pull" and new_mode == "push":
            # Switching from pull to push - remove the poll job
            scheduler_service.remove_pull_poll_job(str(pattern.id))
    except Exception as e:
        # Scheduler may not be available during tests
        logger.debug(f"Could not update scheduler: {e}")

    return pattern


@router.delete("/{pattern_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_index_pattern(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_index_config"))],
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

    # Remove any pull poll job if this was a pull mode index
    if pattern.mode == "pull":
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.remove_pull_poll_job(str(pattern.id))
        except Exception:
            pass  # Scheduler may not be available during tests

    await db.delete(pattern)
    await db.commit()


@router.post("/{pattern_id}/regenerate-token", response_model=IndexPatternTokenResponse)
async def regenerate_auth_token(
    pattern_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_index_config"))],
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
    include_multi_fields: bool = False,
):
    """
    Get available fields from an index pattern's OpenSearch index.

    Returns a list of field names that can be used as mapping targets or exception fields.

    Query Parameters:
        include_multi_fields: If True, include .keyword and other multi-fields.
                            Default False for cleaner UI dropdowns.
                            Set True when validating field mappings.
    """
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == pattern_id)
    )
    pattern = result.scalar_one_or_none()
    if pattern is None:
        raise HTTPException(status_code=404, detail="Index pattern not found")

    try:
        fields = get_index_fields(opensearch, pattern.pattern, include_multi_fields=include_multi_fields)
        return sorted(fields)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to get index fields: {e}",
        )


@router.get("/{pattern_id}/time-fields", response_model=list[str])
async def get_index_pattern_time_fields(
    pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    opensearch: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Get available date/timestamp fields from an index pattern's OpenSearch index.

    Returns a list of field names that can be used as the timestamp_field for pull mode.
    Only returns fields with date or date_nanos type.
    """
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == pattern_id)
    )
    pattern = result.scalar_one_or_none()
    if pattern is None:
        raise HTTPException(status_code=404, detail="Index pattern not found")

    try:
        fields = get_time_fields(opensearch, pattern.pattern)
        return fields
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to get time fields: {e}",
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
