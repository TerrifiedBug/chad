"""Field mappings API endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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
    os_client=Depends(get_opensearch_client_optional),
):
    """Create a new field mapping with auto-correction for text fields.

    Automatically appends .keyword suffix to text fields that should use exact matching.
    """
    # Get index pattern for field type detection
    target_field = data.target_field
    auto_corrected = False

    if not data.index_pattern_id:
        # Global mapping - skip validation
        import logging
        logging.getLogger(__name__).info("Global mapping - skipping field validation")
    elif os_client:
        from app.services.field_type_detector import auto_correct_field_mapping

        try:
            result = await db.execute(
                select(IndexPattern).where(IndexPattern.id == data.index_pattern_id)
            )
            index_pattern = result.scalar_one_or_none()

            if index_pattern:
                # Auto-correct if target field is a text field
                target_field, auto_corrected = auto_correct_field_mapping(
                    os_client, index_pattern.pattern, data.target_field
                )

                if auto_corrected:
                    # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
                    import logging
                    logging.getLogger(__name__).info(
                        "Auto-corrected field mapping %r -> %r to %r",
                        data.sigma_field, data.target_field, target_field
                    )

                # NEW: Validate field exists
                from app.services.opensearch import get_index_fields, find_similar_fields

                available_fields = get_index_fields(
                    os_client, index_pattern.pattern, include_multi_fields=True
                )

                if available_fields and target_field not in available_fields:
                    similar_fields = find_similar_fields(target_field, available_fields)

                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "field_not_found",
                            "message": f"Field '{target_field}' does not exist in index pattern '{index_pattern.name}'",
                            "field": target_field,
                            "index_pattern": index_pattern.name,
                            "suggestions": similar_fields[:5],
                        }
                    )

                # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
                import logging
                logging.getLogger(__name__).info(
                    "Validated field mapping %r -> %r (exists in %d available fields)",
                    data.sigma_field, target_field, len(available_fields)
                )
        except HTTPException:
            raise  # Re-raise our validation error
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to auto-correct/validate field mapping: %s. Using user-provided value.",
                e
            )

    try:
        mapping = await create_mapping(
            db,
            sigma_field=data.sigma_field,
            target_field=target_field,
            index_pattern_id=data.index_pattern_id,
            created_by=current_user.id,
            origin=data.origin,
            confidence=data.confidence,
        )
    except IntegrityError as e:
        # Check if it's a duplicate key error for the same sigma_field + index_pattern_id
        if "uq_mapping_scope_field" in str(e):
            # Fetch the existing mapping to provide helpful info
            from app.models.field_mapping import FieldMapping

            result = await db.execute(
                select(FieldMapping).where(
                    FieldMapping.sigma_field == data.sigma_field,
                    FieldMapping.index_pattern_id == data.index_pattern_id,
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                # Check if the existing mapping already uses .keyword
                if existing.target_field.endswith(".keyword"):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "error": "duplicate_mapping",
                            "message": f"Field mapping '{data.sigma_field}' already exists for this index pattern.",
                            "existing_mapping": {
                                "id": str(existing.id),
                                "sigma_field": existing.sigma_field,
                                "target_field": existing.target_field,
                                "note": "This mapping already uses .keyword suffix - no update needed",
                            },
                            "suggestion": "Update the existing mapping instead of creating a duplicate, or delete it first.",
                        },
                    )
                else:
                    # Existing mapping doesn't use .keyword - suggest update
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "error": "duplicate_mapping",
                            "message": f"Field mapping '{data.sigma_field}' already exists for this index pattern.",
                            "existing_mapping": {
                                "id": str(existing.id),
                                "sigma_field": existing.sigma_field,
                                "target_field": existing.target_field,
                            },
                            "auto_correction": {
                                "current": existing.target_field,
                                "recommended": f"{existing.target_field}.keyword",
                                "note": "The existing mapping should be updated to use .keyword for proper matching",
                            },
                            "suggestion": f"Update mapping ID {existing.id} to use '{existing.target_field}.keyword' instead.",
                        },
                    )
        # Re-raise if it's a different integrity error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Database integrity error: {str(e)}",
        )

    audit_data = {
        "sigma_field": data.sigma_field,
        "target_field": data.target_field,
        "final_target_field": target_field,
        "auto_corrected": auto_corrected,
    }

    await audit_log(
        db,
        current_user.id,
        "field_mapping.create",
        "field_mapping",
        str(mapping.id),
        audit_data,
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
    os_client=Depends(get_opensearch_client_optional),
):
    """Update an existing field mapping with auto-correction for text fields.

    Automatically appends .keyword suffix to text fields that should use exact matching.
    """
    # Get the mapping to find its index pattern
    from sqlalchemy import select
    from app.models.field_mapping import FieldMapping

    result = await db.execute(select(FieldMapping).where(FieldMapping.id == mapping_id))
    mapping = result.scalar_one_or_none()
    if mapping is None:
        raise HTTPException(status_code=404, detail="Mapping not found")

    # Auto-correct if target_field is being updated
    target_field = data.target_field
    auto_corrected = False

    if data.target_field and mapping.index_pattern_id and os_client:
        from app.services.field_type_detector import auto_correct_field_mapping

        try:
            # Get index pattern
            result = await db.execute(
                select(IndexPattern).where(IndexPattern.id == mapping.index_pattern_id)
            )
            index_pattern = result.scalar_one_or_none()

            if index_pattern:
                # Auto-correct if target field is a text field
                target_field, auto_corrected = auto_correct_field_mapping(
                    os_client, index_pattern.pattern, data.target_field
                )

                if auto_corrected:
                    # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
                    import logging
                    logging.getLogger(__name__).info(
                        "Auto-corrected field mapping %r -> %r to %r",
                        mapping.sigma_field, data.target_field, target_field
                    )

                # NEW: Validate new target field if changed
                from app.services.opensearch import get_index_fields, find_similar_fields

                available_fields = get_index_fields(
                    os_client, index_pattern.pattern, include_multi_fields=True
                )

                if available_fields and target_field not in available_fields:
                    similar_fields = find_similar_fields(target_field, available_fields)

                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "field_not_found",
                            "message": f"Field '{target_field}' does not exist in index pattern",
                            "field": target_field,
                            "suggestions": similar_fields[:5],
                        }
                    )

                # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
                import logging
                logging.getLogger(__name__).info(
                    "Validated field mapping update %r -> %r (exists in %d available fields)",
                    mapping.sigma_field, target_field, len(available_fields)
                )
        except HTTPException:
            raise  # Re-raise our validation error
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to auto-correct/validate field mapping: %s. Using user-provided value.",
                e
            )

    # Increment version if target_field changed
    if data.target_field and data.target_field != mapping.target_field:
        # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
        import logging
        logger = logging.getLogger(__name__)

        logger.info("Field mapping changed: %r -> %r to %r", mapping.sigma_field, mapping.target_field, target_field)

        mapping.version += 1
        await db.flush()

        # Find affected rules and bump their versions
        from app.services.field_mapping import get_rules_using_mapping

        affected_rules = await get_rules_using_mapping(db, mapping.id)
        # lgtm[py/log-injection] Rule count is not sensitive information
        logger = logging.getLogger(__name__)
        logger.info("Found %d rules affected by field mapping change", len(affected_rules))

        from datetime import datetime, timezone
        from app.models.rule import RuleVersion

        for rule in affected_rules:
            # Get the current latest version number
            current_version = rule.versions[0].version_number if rule.versions else 1
            new_version_number = current_version + 1

            # Create new version
            new_version = RuleVersion(
                rule_id=rule.id,
                version_number=new_version_number,
                yaml_content=rule.yaml_content,
                changed_by=current_user.id,
                change_reason=f"Field mapping updated: {mapping.sigma_field} now maps to {data.target_field}",
                created_at=datetime.now(timezone.utc)
            )
            db.add(new_version)

        # Commit immediately
        await db.commit()

    # Update the mapping with corrected field
    updated_mapping = await update_mapping(
        db,
        mapping_id,
        target_field=target_field,
        origin=data.origin,
        confidence=data.confidence,
    )

    if updated_mapping is None:
        raise HTTPException(status_code=404, detail="Mapping not found")

    audit_data = {
        "changes": data.model_dump(exclude_none=True),
        "final_target_field": target_field,
        "auto_corrected": auto_corrected,
    }

    await audit_log(
        db,
        current_user.id,
        "field_mapping.update",
        "field_mapping",
        str(mapping_id),
        audit_data,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return updated_mapping


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

    # Get AI suggestions and auto-correct
    from app.services.field_type_detector import auto_correct_field_mapping

    try:
        suggestions = await suggest_mappings(
            db, data.sigma_fields, log_fields, data.logsource
        )

        # Auto-correct AI suggestions to use .keyword for text fields
        corrected_suggestions = []
        for s in suggestions:
            corrected_field, was_corrected = auto_correct_field_mapping(
                os_client, index_pattern.pattern, s.target_field
            )

            if was_corrected:
                # lgtm[py/log-injection] Field names are schema metadata, not sensitive data
                import logging
                logging.getLogger(__name__).info(
                    "Auto-corrected AI suggestion %r -> %r to %r",
                    s.sigma_field, s.target_field, corrected_field
                )
                # Update reason to explain the correction
                reason = f"{s.reason} (Auto-corrected to use .keyword for exact matching)"
            else:
                reason = s.reason

            corrected_suggestions.append(
                AISuggestionResponse(
                    sigma_field=s.sigma_field,
                    target_field=corrected_field,
                    confidence=s.confidence,
                    reason=reason,
                )
            )

        return corrected_suggestions
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
