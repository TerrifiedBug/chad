"""Correlation rules API - manage multi-rule alert correlations."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.api.deps import get_current_user, get_db, require_permission_dep
from app.models.user import User
from app.models.correlation_rule import CorrelationRule
from app.models.rule import Rule
from app.schemas.correlation import (
    CorrelationRuleCreate,
    CorrelationRuleListResponse,
    CorrelationRuleResponse,
    CorrelationRuleUpdate,
)

router = APIRouter(prefix="/correlation-rules", tags=["correlation"])


@router.get("", response_model=CorrelationRuleListResponse)
async def list_correlation_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    include_disabled: bool = Query(False),
):
    """List all correlation rules."""
    query = select(CorrelationRule)

    if not include_disabled:
        query = query.where(CorrelationRule.is_enabled == True)

    query = query.order_by(CorrelationRule.created_at.desc())

    result = await db.execute(query)
    rules = result.scalars().all()

    # Enrich with rule titles
    rule_responses = []
    for rule in rules:
        # Get rule A title
        rule_a_result = await db.execute(
            select(Rule.title).where(Rule.id == rule.rule_a_id)
        )
        rule_a_title = rule_a_result.scalar_one_or_none()

        # Get rule B title
        rule_b_result = await db.execute(
            select(Rule.title).where(Rule.id == rule.rule_b_id)
        )
        rule_b_title = rule_b_result.scalar_one_or_none()

        rule_responses.append(
            CorrelationRuleResponse(
                id=str(rule.id),
                name=rule.name,
                rule_a_id=str(rule.rule_a_id),
                rule_b_id=str(rule.rule_b_id),
                entity_field=rule.entity_field,
                time_window_minutes=rule.time_window_minutes,
                severity=rule.severity,
                is_enabled=rule.is_enabled,
                created_at=rule.created_at,
                updated_at=rule.updated_at,
                created_by=str(rule.created_by) if rule.created_by else None,
                rule_a_title=rule_a_title,
                rule_b_title=rule_b_title,
            )
        )

    return CorrelationRuleListResponse(
        correlation_rules=rule_responses,
        total=len(rule_responses),
    )


@router.get("/{rule_id}", response_model=CorrelationRuleResponse)
async def get_correlation_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get a single correlation rule by ID."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Get rule titles
    rule_a_result = await db.execute(
        select(Rule.title).where(Rule.id == rule.rule_a_id)
    )
    rule_a_title = rule_a_result.scalar_one_or_none()

    rule_b_result = await db.execute(
        select(Rule.title).where(Rule.id == rule.rule_b_id)
    )
    rule_b_title = rule_b_result.scalar_one_or_none()

    return CorrelationRuleResponse(
        id=str(rule.id),
        name=rule.name,
        rule_a_id=str(rule.rule_a_id),
        rule_b_id=str(rule.rule_b_id),
        entity_field=rule.entity_field,
        time_window_minutes=rule.time_window_minutes,
        severity=rule.severity,
        is_enabled=rule.is_enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        created_by=str(rule.created_by) if rule.created_by else None,
        rule_a_title=rule_a_title,
        rule_b_title=rule_b_title,
    )


@router.post("", response_model=CorrelationRuleResponse)
async def create_correlation_rule(
    data: CorrelationRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Create a new correlation rule."""
    # Validate rules exist
    rule_a_result = await db.execute(
        select(Rule).where(Rule.id == UUID(data.rule_a_id))
    )
    rule_a = rule_a_result.scalar_one_or_none()
    if not rule_a:
        raise HTTPException(404, f"Rule A (ID: {data.rule_a_id}) not found")

    rule_b_result = await db.execute(
        select(Rule).where(Rule.id == UUID(data.rule_b_id))
    )
    rule_b = rule_b_result.scalar_one_or_none()
    if not rule_b:
        raise HTTPException(404, f"Rule B (ID: {data.rule_b_id}) not found")

    # Check for duplicate
    existing = await db.execute(
        select(CorrelationRule).where(
            (CorrelationRule.rule_a_id == UUID(data.rule_a_id))
            & (CorrelationRule.rule_b_id == UUID(data.rule_b_id))
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            400, "Correlation rule for this rule pair already exists"
        )

    # Create the correlation rule
    rule = CorrelationRule(
        name=data.name,
        rule_a_id=UUID(data.rule_a_id),
        rule_b_id=UUID(data.rule_b_id),
        entity_field=data.entity_field,
        time_window_minutes=data.time_window_minutes,
        severity=data.severity,
        is_enabled=data.is_enabled,
        created_by=current_user.id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    return CorrelationRuleResponse(
        id=str(rule.id),
        name=rule.name,
        rule_a_id=str(rule.rule_a_id),
        rule_b_id=str(rule.rule_b_id),
        entity_field=rule.entity_field,
        time_window_minutes=rule.time_window_minutes,
        severity=rule.severity,
        is_enabled=rule.is_enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        created_by=str(rule.created_by),
        rule_a_title=rule_a.title,
        rule_b_title=rule_b.title,
    )


@router.patch("/{rule_id}", response_model=CorrelationRuleResponse)
async def update_correlation_rule(
    rule_id: str,
    data: CorrelationRuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Update fields
    if data.name is not None:
        rule.name = data.name
    if data.entity_field is not None:
        rule.entity_field = data.entity_field
    if data.time_window_minutes is not None:
        rule.time_window_minutes = data.time_window_minutes
    if data.severity is not None:
        rule.severity = data.severity
    if data.is_enabled is not None:
        rule.is_enabled = data.is_enabled

    await db.commit()
    await db.refresh(rule)

    # Get rule titles
    rule_a_result = await db.execute(
        select(Rule.title).where(Rule.id == rule.rule_a_id)
    )
    rule_a_title = rule_a_result.scalar_one_or_none()

    rule_b_result = await db.execute(
        select(Rule.title).where(Rule.id == rule.rule_b_id)
    )
    rule_b_title = rule_b_result.scalar_one_or_none()

    return CorrelationRuleResponse(
        id=str(rule.id),
        name=rule.name,
        rule_a_id=str(rule.rule_a_id),
        rule_b_id=str(rule.rule_b_id),
        entity_field=rule.entity_field,
        time_window_minutes=rule.time_window_minutes,
        severity=rule.severity,
        is_enabled=rule.is_enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        created_by=str(rule.created_by),
        rule_a_title=rule_a_title,
        rule_b_title=rule_b_title,
    )


@router.delete("/{rule_id}")
async def delete_correlation_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Delete a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    await db.delete(rule)
    await db.commit()

    return {"message": "Correlation rule deleted"}
