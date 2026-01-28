"""Correlation rules API - manage multi-rule alert correlations."""

from datetime import datetime, UTC
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from uuid import UUID

from app.api.deps import get_current_user, get_db, require_permission_dep
from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.correlation_rule import CorrelationRule, CorrelationRuleVersion
from app.models.correlation_rule_comment import CorrelationRuleComment
from app.models.rule import Rule
from app.services.audit import audit_log
from app.utils.request import get_client_ip
from app.schemas.correlation import (
    CorrelationActivityItem,
    CorrelationRuleCommentCreate,
    CorrelationRuleCommentResponse,
    CorrelationRuleCreate,
    CorrelationRuleDeployRequest,
    CorrelationRuleListResponse,
    CorrelationRuleResponse,
    CorrelationRuleRollbackResponse,
    CorrelationRuleUpdate,
    CorrelationRuleVersionResponse,
)

router = APIRouter(prefix="/correlation-rules", tags=["correlation"])


def build_correlation_response(
    rule: CorrelationRule,
    rule_a_title: str | None,
    rule_b_title: str | None,
    last_edited_by: str | None = None,
    rule_a_deployed: bool = True,
    rule_b_deployed: bool = True,
) -> CorrelationRuleResponse:
    """Build a CorrelationRuleResponse from a rule."""
    return CorrelationRuleResponse(
        id=str(rule.id),
        name=rule.name,
        rule_a_id=str(rule.rule_a_id),
        rule_b_id=str(rule.rule_b_id),
        entity_field=rule.entity_field,
        time_window_minutes=rule.time_window_minutes,
        severity=rule.severity,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        created_by=str(rule.created_by) if rule.created_by else None,
        last_edited_by=last_edited_by,
        deployed_at=rule.deployed_at,
        deployed_version=rule.deployed_version,
        current_version=rule.current_version,
        needs_redeploy=rule.needs_redeploy,
        rule_a_title=rule_a_title,
        rule_b_title=rule_b_title,
        rule_a_deployed=rule_a_deployed,
        rule_b_deployed=rule_b_deployed,
    )


async def get_rule_info(db: AsyncSession, rule_a_id: UUID, rule_b_id: UUID) -> dict:
    """Get the titles and deployment status for rule A and rule B."""
    from app.models.rule import RuleStatus

    rule_a_result = await db.execute(select(Rule.title, Rule.status).where(Rule.id == rule_a_id))
    rule_a_row = rule_a_result.one_or_none()

    rule_b_result = await db.execute(select(Rule.title, Rule.status).where(Rule.id == rule_b_id))
    rule_b_row = rule_b_result.one_or_none()

    return {
        "rule_a_title": rule_a_row[0] if rule_a_row else None,
        "rule_b_title": rule_b_row[0] if rule_b_row else None,
        "rule_a_deployed": rule_a_row[1] == RuleStatus.DEPLOYED if rule_a_row else False,
        "rule_b_deployed": rule_b_row[1] == RuleStatus.DEPLOYED if rule_b_row else False,
    }


async def get_last_edited_by(db: AsyncSession, rule_id: str) -> str | None:
    """Get the last editor's email from audit logs."""
    from app.models.audit_log import AuditLog

    audit_result = await db.execute(
        select(AuditLog, User)
        .join(User, AuditLog.user_id == User.id, isouter=True)
        .where(AuditLog.resource_type == "correlation_rule")
        .where(AuditLog.resource_id == rule_id)
        .where(AuditLog.action.in_(["correlation_rule_created", "correlation_rule_updated"]))
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    )
    audit_entry = audit_result.first()
    if audit_entry and audit_entry.User:
        return audit_entry.User.email
    return None


@router.get("", response_model=CorrelationRuleListResponse)
async def list_correlation_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    include_undeployed: bool = Query(True),
):
    """List all correlation rules."""
    query = select(CorrelationRule)

    if not include_undeployed:
        query = query.where(CorrelationRule.deployed_at.isnot(None))

    query = query.order_by(CorrelationRule.created_at.desc())

    result = await db.execute(query)
    rules = result.scalars().all()

    rule_responses = []
    for rule in rules:
        rule_info = await get_rule_info(db, rule.rule_a_id, rule.rule_b_id)
        last_edited_by = await get_last_edited_by(db, str(rule.id))
        rule_responses.append(
            build_correlation_response(
                rule,
                rule_info["rule_a_title"],
                rule_info["rule_b_title"],
                last_edited_by,
                rule_info["rule_a_deployed"],
                rule_info["rule_b_deployed"],
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

    rule_info = await get_rule_info(db, rule.rule_a_id, rule.rule_b_id)
    last_edited_by = await get_last_edited_by(db, rule_id)

    return build_correlation_response(
        rule,
        rule_info["rule_a_title"],
        rule_info["rule_b_title"],
        last_edited_by,
        rule_info["rule_a_deployed"],
        rule_info["rule_b_deployed"],
    )


@router.get("/{rule_id}/versions", response_model=list[CorrelationRuleVersionResponse])
async def list_correlation_rule_versions(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all versions of a correlation rule."""
    # Verify rule exists
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Get versions with author info
    result = await db.execute(
        select(CorrelationRuleVersion)
        .options(selectinload(CorrelationRuleVersion.author))
        .where(CorrelationRuleVersion.correlation_rule_id == UUID(rule_id))
        .order_by(CorrelationRuleVersion.version_number.desc())
    )
    versions = result.scalars().all()

    return [
        CorrelationRuleVersionResponse(
            id=str(v.id),
            version_number=v.version_number,
            name=v.name,
            rule_a_id=str(v.rule_a_id),
            rule_b_id=str(v.rule_b_id),
            entity_field=v.entity_field,
            time_window_minutes=v.time_window_minutes,
            severity=v.severity,
            changed_by=str(v.changed_by),
            changed_by_email=v.author.email if v.author else None,
            change_reason=v.change_reason,
            created_at=v.created_at,
        )
        for v in versions
    ]


@router.post("", response_model=CorrelationRuleResponse)
async def create_correlation_rule(
    data: CorrelationRuleCreate,
    request: Request,
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
        created_by=current_user.id,
        current_version=1,
    )
    db.add(rule)
    await db.flush()  # Get the rule ID before creating version

    # Create initial version
    version = CorrelationRuleVersion(
        correlation_rule_id=rule.id,
        version_number=1,
        name=rule.name,
        rule_a_id=rule.rule_a_id,
        rule_b_id=rule.rule_b_id,
        entity_field=rule.entity_field,
        time_window_minutes=rule.time_window_minutes,
        severity=rule.severity,
        changed_by=current_user.id,
        change_reason=data.change_reason,
    )
    db.add(version)

    await db.commit()
    await db.refresh(rule)

    # Log audit event
    await audit_log(
        db,
        current_user.id,
        "correlation_rule_created",
        "correlation_rule",
        str(rule.id),
        {
            "name": rule.name,
            "rule_a_id": str(rule.rule_a_id),
            "rule_b_id": str(rule.rule_b_id),
            "entity_field": rule.entity_field,
            "time_window_minutes": rule.time_window_minutes,
            "severity": rule.severity,
            "change_reason": data.change_reason,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return build_correlation_response(rule, rule_a.title, rule_b.title, current_user.email)


@router.patch("/{rule_id}", response_model=CorrelationRuleResponse)
async def update_correlation_rule(
    rule_id: str,
    data: CorrelationRuleUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Track what changed
    changes = {}
    has_versioned_changes = False

    if data.name is not None and data.name != rule.name:
        changes["name"] = {"old": rule.name, "new": data.name}
        has_versioned_changes = True
    if data.entity_field is not None and data.entity_field != rule.entity_field:
        changes["entity_field"] = {"old": rule.entity_field, "new": data.entity_field}
        has_versioned_changes = True
    if data.time_window_minutes is not None and data.time_window_minutes != rule.time_window_minutes:
        changes["time_window_minutes"] = {"old": rule.time_window_minutes, "new": data.time_window_minutes}
        has_versioned_changes = True
    if data.severity is not None and data.severity != rule.severity:
        changes["severity"] = {"old": rule.severity, "new": data.severity}
        has_versioned_changes = True

    # Update fields
    if data.name is not None:
        rule.name = data.name
    if data.entity_field is not None:
        rule.entity_field = data.entity_field
    if data.time_window_minutes is not None:
        rule.time_window_minutes = data.time_window_minutes
    if data.severity is not None:
        rule.severity = data.severity

    # Create new version if versioned fields changed
    if has_versioned_changes:
        rule.current_version += 1
        version = CorrelationRuleVersion(
            correlation_rule_id=rule.id,
            version_number=rule.current_version,
            name=rule.name,
            rule_a_id=rule.rule_a_id,
            rule_b_id=rule.rule_b_id,
            entity_field=rule.entity_field,
            time_window_minutes=rule.time_window_minutes,
            severity=rule.severity,
            changed_by=current_user.id,
            change_reason=data.change_reason or "Updated correlation rule",
        )
        db.add(version)

    await db.commit()
    await db.refresh(rule)

    # Log audit event
    await audit_log(
        db,
        current_user.id,
        "correlation_rule_updated",
        "correlation_rule",
        rule_id,
        {
            "name": rule.name,
            "changes": changes,
            "change_reason": data.change_reason,
            "new_version": rule.current_version if has_versioned_changes else None,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    rule_info = await get_rule_info(db, rule.rule_a_id, rule.rule_b_id)
    return build_correlation_response(
        rule,
        rule_info["rule_a_title"],
        rule_info["rule_b_title"],
        current_user.email,
        rule_info["rule_a_deployed"],
        rule_info["rule_b_deployed"],
    )


@router.post("/{rule_id}/deploy", response_model=CorrelationRuleResponse)
async def deploy_correlation_rule(
    rule_id: str,
    data: CorrelationRuleDeployRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Deploy a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Check if linked rules are deployed
    from app.models.rule import Rule, RuleStatus
    linked_rules_result = await db.execute(
        select(Rule).where(Rule.id.in_([rule.rule_a_id, rule.rule_b_id]))
    )
    linked_rules = linked_rules_result.scalars().all()

    undeployed_rules = [r for r in linked_rules if r.status != RuleStatus.DEPLOYED]
    if undeployed_rules:
        undeployed_names = [r.title for r in undeployed_rules]
        raise HTTPException(
            400,
            f"Cannot deploy correlation rule: linked rules are not deployed: {', '.join(undeployed_names)}"
        )

    # Ensure a version snapshot exists for current state
    versions_result = await db.execute(
        select(CorrelationRuleVersion)
        .where(CorrelationRuleVersion.correlation_rule_id == rule.id)
        .order_by(CorrelationRuleVersion.version_number.desc())
        .limit(1)
    )
    latest_version = versions_result.scalar_one_or_none()

    if latest_version is None or latest_version.version_number != rule.current_version:
        # Create version snapshot
        new_version = CorrelationRuleVersion(
            correlation_rule_id=rule.id,
            version_number=rule.current_version,
            name=rule.name,
            rule_a_id=rule.rule_a_id,
            rule_b_id=rule.rule_b_id,
            entity_field=rule.entity_field,
            time_window_minutes=rule.time_window_minutes,
            severity=rule.severity,
            changed_by=current_user.id,
            change_reason=data.change_reason or "Deployed",
        )
        db.add(new_version)

    # Set deployment tracking
    rule.deployed_at = datetime.now(UTC)
    rule.deployed_version = rule.current_version

    await db.commit()
    await db.refresh(rule)

    # Log audit event
    await audit_log(
        db,
        current_user.id,
        "correlation_rule_deployed",
        "correlation_rule",
        rule_id,
        {
            "name": rule.name,
            "deployed_version": rule.deployed_version,
            "change_reason": data.change_reason,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    rule_info = await get_rule_info(db, rule.rule_a_id, rule.rule_b_id)
    return build_correlation_response(
        rule,
        rule_info["rule_a_title"],
        rule_info["rule_b_title"],
        current_user.email,
        rule_info["rule_a_deployed"],
        rule_info["rule_b_deployed"],
    )


@router.post("/{rule_id}/undeploy", response_model=CorrelationRuleResponse)
async def undeploy_correlation_rule(
    rule_id: str,
    data: CorrelationRuleDeployRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Undeploy a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    if rule.deployed_at is None:
        raise HTTPException(400, "Correlation rule is not deployed")

    old_deployed_version = rule.deployed_version

    # Clear deployment tracking
    rule.deployed_at = None
    rule.deployed_version = None

    await db.commit()
    await db.refresh(rule)

    # Log audit event
    await audit_log(
        db,
        current_user.id,
        "correlation_rule_undeployed",
        "correlation_rule",
        rule_id,
        {
            "name": rule.name,
            "previous_deployed_version": old_deployed_version,
            "change_reason": data.change_reason,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    rule_info = await get_rule_info(db, rule.rule_a_id, rule.rule_b_id)
    return build_correlation_response(
        rule,
        rule_info["rule_a_title"],
        rule_info["rule_b_title"],
        current_user.email,
        rule_info["rule_a_deployed"],
        rule_info["rule_b_deployed"],
    )


@router.post("/{correlation_id}/rollback/{version_number}", response_model=CorrelationRuleRollbackResponse)
async def rollback_correlation_rule(
    correlation_id: UUID,
    version_number: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
):
    """Rollback a correlation rule to a previous version."""
    # Fetch rule with versions
    result = await db.execute(
        select(CorrelationRule)
        .where(CorrelationRule.id == correlation_id)
        .options(selectinload(CorrelationRule.versions))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation rule not found",
        )

    # Find target version
    target_version = next(
        (v for v in rule.versions if v.version_number == version_number),
        None
    )
    if target_version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version {version_number} not found",
        )

    # Increment current version
    new_version_number = rule.current_version + 1

    # Create new version with old content
    new_version = CorrelationRuleVersion(
        correlation_rule_id=correlation_id,
        version_number=new_version_number,
        name=target_version.name,
        rule_a_id=target_version.rule_a_id,
        rule_b_id=target_version.rule_b_id,
        entity_field=target_version.entity_field,
        time_window_minutes=target_version.time_window_minutes,
        severity=target_version.severity,
        changed_by=current_user.id,
        change_reason=change_reason,
    )
    db.add(new_version)

    # Update rule fields to match restored version
    rule.name = target_version.name
    rule.rule_a_id = target_version.rule_a_id
    rule.rule_b_id = target_version.rule_b_id
    rule.entity_field = target_version.entity_field
    rule.time_window_minutes = target_version.time_window_minutes
    rule.severity = target_version.severity
    rule.current_version = new_version_number

    await db.commit()
    await audit_log(
        db, current_user.id, "correlation_rule.rollback", "correlation_rule",
        str(rule.id), {"name": rule.name, "from_version": version_number, "to_version": new_version_number},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return CorrelationRuleRollbackResponse(
        success=True,
        new_version_number=new_version_number,
        rolled_back_from=version_number,
    )


@router.delete("/{rule_id}")
async def delete_correlation_rule(
    rule_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Delete a correlation rule."""
    result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(404, "Correlation rule not found")

    # Store rule details for audit log before deletion
    rule_details = {
        "name": rule.name,
        "rule_a_id": str(rule.rule_a_id),
        "rule_b_id": str(rule.rule_b_id),
        "entity_field": rule.entity_field,
        "time_window_minutes": rule.time_window_minutes,
        "severity": rule.severity,
    }

    await db.delete(rule)
    await db.commit()

    # Log audit event
    await audit_log(
        db,
        current_user.id,
        "correlation_rule_deleted",
        "correlation_rule",
        rule_id,
        rule_details,
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"message": "Correlation rule deleted"}


# Correlation Rule Comments Endpoints


@router.get("/{rule_id}/comments", response_model=list[CorrelationRuleCommentResponse])
async def list_correlation_rule_comments(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all comments for a correlation rule."""
    rule_result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation rule not found")

    result = await db.execute(
        select(CorrelationRuleComment)
        .where(CorrelationRuleComment.correlation_rule_id == UUID(rule_id))
        .order_by(CorrelationRuleComment.created_at.desc())
    )
    comments = result.scalars().all()
    return [
        CorrelationRuleCommentResponse(
            id=str(c.id),
            correlation_rule_id=str(c.correlation_rule_id),
            user_id=str(c.user_id) if c.user_id else None,
            user_email=c.user.email if c.user else None,
            content=c.content,
            created_at=c.created_at,
        )
        for c in comments
    ]


@router.post("/{rule_id}/comments", response_model=CorrelationRuleCommentResponse, status_code=status.HTTP_201_CREATED)
async def create_correlation_rule_comment(
    rule_id: str,
    data: CorrelationRuleCommentCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Add a comment to a correlation rule."""
    rule_result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation rule not found")

    comment = CorrelationRuleComment(
        correlation_rule_id=UUID(rule_id),
        user_id=current_user.id,
        content=data.content,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    await audit_log(
        db, current_user.id, "correlation_rule.comment", "correlation_rule", rule_id,
        {"comment_id": str(comment.id)},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return CorrelationRuleCommentResponse(
        id=str(comment.id),
        correlation_rule_id=str(comment.correlation_rule_id),
        user_id=str(comment.user_id),
        user_email=current_user.email,
        content=comment.content,
        created_at=comment.created_at,
    )


# Correlation Rule Activity Timeline Endpoint


@router.get("/{rule_id}/activity", response_model=list[CorrelationActivityItem])
async def get_correlation_rule_activity(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    skip: int = 0,
    limit: int = 50,
):
    """Get unified activity timeline for a correlation rule."""
    # First verify rule exists
    rule_result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.id == UUID(rule_id))
    )
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation rule not found")

    activities: list[CorrelationActivityItem] = []

    # Get versions (from CorrelationRuleVersion model)
    versions_result = await db.execute(
        select(CorrelationRuleVersion)
        .where(CorrelationRuleVersion.correlation_rule_id == UUID(rule_id))
        .options(selectinload(CorrelationRuleVersion.author))
        .order_by(CorrelationRuleVersion.version_number.desc())
    )
    for v in versions_result.scalars():
        activities.append(
            CorrelationActivityItem(
                type="version",
                timestamp=v.created_at,
                user_email=v.author.email if v.author else None,
                data={
                    "version_number": v.version_number,
                    "change_reason": v.change_reason,
                    "name": v.name,
                    "entity_field": v.entity_field,
                    "time_window_minutes": v.time_window_minutes,
                    "severity": v.severity,
                },
            )
        )

    # Get comments
    comments_result = await db.execute(
        select(CorrelationRuleComment)
        .where(CorrelationRuleComment.correlation_rule_id == UUID(rule_id))
        .options(selectinload(CorrelationRuleComment.user))
    )
    for c in comments_result.scalars():
        activities.append(
            CorrelationActivityItem(
                type="comment",
                timestamp=c.created_at,
                user_email=c.user.email if c.user else None,
                data={"content": c.content, "id": str(c.id)},
            )
        )

    # Get deploy/undeploy events from audit log
    audit_result = await db.execute(
        select(AuditLog, User)
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(
            AuditLog.resource_id == rule_id,
            AuditLog.action.in_(["correlation_rule_deployed", "correlation_rule_undeployed"]),
        )
    )
    for a, user in audit_result:
        activities.append(
            CorrelationActivityItem(
                type="deploy" if a.action == "correlation_rule_deployed" else "undeploy",
                timestamp=a.created_at,
                user_email=user.email if user else None,
                data=a.details or {},
            )
        )

    # Sort by timestamp descending and apply pagination
    activities.sort(key=lambda x: x.timestamp, reverse=True)
    return activities[skip : skip + limit]
