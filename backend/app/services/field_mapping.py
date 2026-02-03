"""Field mapping service for Sigma to log field translations."""

from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.field_mapping import FieldMapping, MappingOrigin


async def resolve_mappings(
    db: AsyncSession,
    sigma_fields: list[str],
    index_pattern_id: UUID,
) -> dict[str, str | None]:
    """
    Resolve Sigma field names to target log field names.

    Resolution order:
    1. Per-index mapping (index_pattern_id matches)
    2. None if no mapping found

    Returns:
        Dict mapping sigma_field -> target_field (or None if unmapped)
    """
    if not sigma_fields:
        return {}

    # Fetch per-index mappings only (global mappings removed)
    result = await db.execute(
        select(FieldMapping).where(
            and_(
                FieldMapping.sigma_field.in_(sigma_fields),
                FieldMapping.index_pattern_id == index_pattern_id,
            )
        )
    )
    mappings = result.scalars().all()

    # Build lookup
    resolved: dict[str, str | None] = {field: None for field in sigma_fields}

    for mapping in mappings:
        resolved[mapping.sigma_field] = mapping.target_field

    return resolved


async def get_mappings(
    db: AsyncSession,
    index_pattern_id: UUID | None = None,
) -> list[FieldMapping]:
    """
    Get field mappings, optionally filtered by index pattern.

    Args:
        index_pattern_id: If provided, filter to this index pattern.
                         If None, get global mappings only.
    """
    if index_pattern_id is None:
        query = select(FieldMapping).where(FieldMapping.index_pattern_id.is_(None))
    else:
        query = select(FieldMapping).where(
            FieldMapping.index_pattern_id == index_pattern_id
        )

    result = await db.execute(query.order_by(FieldMapping.sigma_field))
    return list(result.scalars().all())


async def create_mapping(
    db: AsyncSession,
    sigma_field: str,
    target_field: str,
    created_by: UUID,
    index_pattern_id: UUID,  # Now required
    origin: MappingOrigin = MappingOrigin.MANUAL,
    confidence: float | None = None,
) -> FieldMapping:
    """Create a new field mapping."""
    mapping = FieldMapping(
        sigma_field=sigma_field,
        target_field=target_field,
        index_pattern_id=index_pattern_id,
        origin=origin,
        confidence=confidence,
        created_by=created_by,
    )
    db.add(mapping)
    await db.commit()
    await db.refresh(mapping)
    return mapping


async def update_mapping(
    db: AsyncSession,
    mapping_id: UUID,
    target_field: str | None = None,
    origin: MappingOrigin | None = None,
    confidence: float | None = None,
) -> FieldMapping | None:
    """Update an existing field mapping."""
    result = await db.execute(
        select(FieldMapping).where(FieldMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()

    if mapping is None:
        return None

    if target_field is not None:
        mapping.target_field = target_field
    if origin is not None:
        mapping.origin = origin
    if confidence is not None:
        mapping.confidence = confidence

    await db.commit()
    await db.refresh(mapping)
    return mapping


async def delete_mapping(db: AsyncSession, mapping_id: UUID) -> bool:
    """Delete a field mapping. Returns True if deleted."""
    result = await db.execute(
        select(FieldMapping).where(FieldMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()

    if mapping is None:
        return False

    await db.delete(mapping)
    await db.commit()
    return True


async def get_rules_using_mapping(
    db: AsyncSession,
    mapping_id: UUID,
) -> list:
    """Get all rules that use a specific field mapping."""
    import logging

    from sqlalchemy.orm import selectinload

    from app.models.rule import Rule

    logger = logging.getLogger(__name__)

    # Get the mapping
    result = await db.execute(select(FieldMapping).where(FieldMapping.id == mapping_id))
    mapping = result.scalar_one_or_none()

    if not mapping:
        logger.warning("Mapping %s not found", mapping_id)
        return []

    logger.info("Checking for rules using field mapping: %s -> %s", mapping.sigma_field, mapping.target_field)

    # Find all rules for this index pattern
    rules_result = await db.execute(
        select(Rule)
        .options(selectinload(Rule.versions))
        .where(Rule.index_pattern_id == mapping.index_pattern_id)
    )
    rules = rules_result.scalars().all()

    logger.info("Found %d rules for index pattern %s", len(rules), mapping.index_pattern_id)

    # Check each rule's YAML for the sigma_field
    affected_rules = []
    from app.services.sigma import sigma_service

    for rule in rules:
        try:
            # Parse YAML into SigmaRule object
            sigma_rule = sigma_service.parse_rule(rule.yaml_content)
            if sigma_rule is None:
                logger.warning("  -> Failed to parse rule %s: Could not parse Sigma rule", rule.id)
                continue

            # Extract fields from the parsed rule
            fields = sigma_service.extract_fields(sigma_rule)

            logger.info("Rule %s (%s) has fields: %s", rule.id, rule.title, list(fields)[:10])  # Log first 10 fields

            if mapping.sigma_field in fields:
                logger.info("  -> Rule %s USES this field mapping!", rule.id)
                affected_rules.append(rule)
        except Exception as e:
            # If we can't parse the YAML, skip this rule
            logger.warning("  -> Failed to parse rule %s: %s", rule.id, e)
            continue

    logger.info("Total affected rules: %d", len(affected_rules))
    return affected_rules
