"""Rule metadata sub-router: fields, linked correlations, bulk delete, comments, activity, and versions."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_current_user,
    get_opensearch_client,
    get_opensearch_client_optional,
    require_permission_dep,
)
from app.api.rules._shared import (
    ActivityItem,
    RuleCommentCreate,
    RuleCommentResponse,
)
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.correlation_rule import CorrelationRule
from app.models.rule import Rule, RuleVersion
from app.models.rule_comment import RuleComment
from app.models.user import User
from app.schemas.bulk import BulkOperationRequest, BulkOperationResult
from app.schemas.rule import (
    RuleVersionResponse,
)
from app.services.audit import audit_log
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


class RuleFieldsResponse(BaseModel):
    """Available fields from a rule's index pattern, filtered for correlation entities."""
    fields: list[str]  # List of field names suitable for correlation


@router.get("/{rule_id}/fields", response_model=RuleFieldsResponse)
async def get_rule_fields(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Get available fields from a rule's index pattern for correlation.

    Returns fields that are suitable for entity correlation (IPs, names, IDs).
    Filters out noise fields and shows only meaningful correlation entities.
    """
    # Get rule with index pattern
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule.index_pattern is None:
        raise HTTPException(status_code=400, detail="Rule has no index pattern")

    # Get fields from OpenSearch index (exclude .keyword for correlation field dropdown)
    try:
        index_pattern = rule.index_pattern.pattern
        # Get all fields from the index (no .keyword multi-fields for correlation)
        all_fields = await get_index_fields(os_client, index_pattern, include_multi_fields=False)

        # Filter to correlation-relevant fields (entity fields)
        # These are fields that make sense to correlate events on
        correlation_fields = []

        # Patterns that indicate good correlation entities
        entity_patterns = [
            "ip", "address", "hostname", "host", "name", "id",
            "user", "username", "email", "domain", "fqdn",
            "process", "executable", "command", "hash",
            "file", "path", "url", "uri"
        ]

        # Noise patterns to exclude
        noise_patterns = [
            "message", "@timestamp", "timestamp", "tags", "labels",
            "offset", "position", "version", "agent", "ecs",
            "event.", "cloud.", "service."
        ]

        for field in all_fields:
            field_lower = field.lower()

            # Skip noise fields
            if any(field_lower.startswith(pattern) for pattern in noise_patterns):
                continue

            # Include if it looks like an entity field
            if any(pattern in field_lower for pattern in entity_patterns):
                correlation_fields.append(field)

        # Sort and deduplicate
        correlation_fields = sorted(set(correlation_fields))

        return RuleFieldsResponse(fields=correlation_fields)

    except Exception:
        # If we can't get fields from OpenSearch, return empty list
        # This allows the UI to still function
        return RuleFieldsResponse(fields=[])


class LinkedCorrelationRule(BaseModel):
    """A correlation rule that references this rule."""

    id: str
    name: str
    deployed: bool


class LinkedCorrelationsResponse(BaseModel):
    """Response with correlation rules that reference this rule."""

    correlations: list[LinkedCorrelationRule]


@router.get("/{rule_id}/linked-correlations", response_model=LinkedCorrelationsResponse)
async def get_linked_correlations(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    deployed_only: bool = True,
):
    """
    Get correlation rules that reference this rule.

    Returns a list of correlation rules where this rule is either rule_a or rule_b.
    By default, only returns deployed correlations (useful for undeploy warnings).
    """

    # Find correlation rules that reference this rule
    query = select(CorrelationRule).where(
        or_(
            CorrelationRule.rule_a_id == rule_id,
            CorrelationRule.rule_b_id == rule_id,
        )
    )

    # Filter to only deployed correlations if requested
    if deployed_only:
        query = query.where(CorrelationRule.deployed_at.isnot(None))

    result = await db.execute(query)
    correlations = result.scalars().all()

    return LinkedCorrelationsResponse(
        correlations=[
            LinkedCorrelationRule(
                id=str(corr.id),
                name=corr.name,
                deployed=corr.deployed_at is not None,
            )
            for corr in correlations
        ]
    )


@router.post("/bulk/delete", response_model=BulkOperationResult)
async def bulk_delete_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Delete multiple rules."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            result = await db.execute(
                select(Rule)
                .where(Rule.id == rule_id)
                .options(selectinload(Rule.index_pattern))
            )
            rule = result.scalar_one_or_none()
            if rule:
                # Undeploy from OpenSearch if deployed
                if rule.deployed_at is not None and os_client is not None:
                    percolator = PercolatorService(os_client)
                    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
                    percolator.undeploy_rule(percolator_index, str(rule.id))

                # Undeploy any correlation rules that reference this rule
                corr_result = await db.execute(
                    select(CorrelationRule).where(
                        or_(
                            CorrelationRule.rule_a_id == rule_id,
                            CorrelationRule.rule_b_id == rule_id,
                        ),
                        CorrelationRule.deployed_at.isnot(None),
                    )
                )
                for corr_rule in corr_result.scalars().all():
                    corr_rule.deployed_at = None
                    corr_rule.deployed_version = None

                await db.delete(rule)
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_delete", "rule", None,
        {"count": len(success), "rule_ids": success, "change_reason": data.change_reason},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


# Rule Comments Endpoints


@router.get("/{rule_id}/comments", response_model=list[RuleCommentResponse])
async def list_rule_comments(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all comments for a rule."""
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    result = await db.execute(
        select(RuleComment)
        .where(RuleComment.rule_id == rule_id)
        .order_by(RuleComment.created_at.desc())
    )
    comments = result.scalars().all()
    return [
        RuleCommentResponse(
            id=str(c.id),
            rule_id=str(c.rule_id),
            user_id=str(c.user_id) if c.user_id else None,
            user_email=c.user.email if c.user else None,
            content=c.content,
            created_at=c.created_at,
        )
        for c in comments
    ]


@router.post("/{rule_id}/comments", response_model=RuleCommentResponse, status_code=status.HTTP_201_CREATED)
async def create_rule_comment(
    rule_id: UUID,
    data: RuleCommentCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Add a comment to a rule."""
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    comment = RuleComment(
        rule_id=rule_id,
        user_id=current_user.id,
        content=data.content,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    await audit_log(
        db, current_user.id, "rule.comment", "rule", str(rule_id),
        {"comment_id": str(comment.id)},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return RuleCommentResponse(
        id=str(comment.id),
        rule_id=str(comment.rule_id),
        user_id=str(comment.user_id),
        user_email=current_user.email,
        content=comment.content,
        created_at=comment.created_at,
    )


# Rule Activity Timeline Endpoint


@router.get("/{rule_id}/activity", response_model=list[ActivityItem])
async def get_rule_activity(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    skip: int = 0,
    limit: int = 50,
):
    """Get unified activity timeline for a rule."""
    # First verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    activities: list[ActivityItem] = []

    # Get versions (from RuleVersion model)
    versions_result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.rule_id == rule_id)
        .options(selectinload(RuleVersion.author))
        .order_by(RuleVersion.version_number.desc())
    )
    for v in versions_result.scalars():
        activities.append(
            ActivityItem(
                type="version",
                timestamp=v.created_at,
                user_email=v.author.email if v.author else None,
                data={
                    "version_number": v.version_number,
                    "yaml_content": v.yaml_content,
                    "change_reason": v.change_reason,
                },
            )
        )

    # Get comments
    comments_result = await db.execute(
        select(RuleComment)
        .where(RuleComment.rule_id == rule_id)
        .options(selectinload(RuleComment.user))
    )
    for c in comments_result.scalars():
        activities.append(
            ActivityItem(
                type="comment",
                timestamp=c.created_at,
                user_email=c.user.email if c.user else None,
                data={"content": c.content, "id": str(c.id)},
            )
        )

    # Get deploy/undeploy events from audit log
    # Join with User to get email
    audit_result = await db.execute(
        select(AuditLog, User)
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(
            AuditLog.resource_id == str(rule_id),
            AuditLog.action.in_(["rule.deploy", "rule.undeploy"]),
        )
    )
    for a, user in audit_result:
        activities.append(
            ActivityItem(
                type="deploy" if a.action == "rule.deploy" else "undeploy",
                timestamp=a.created_at,
                user_email=user.email if user else None,
                data=a.details or {},
            )
        )

    # Sort by timestamp descending
    activities.sort(key=lambda x: x.timestamp, reverse=True)

    # Apply pagination
    return activities[skip:skip + limit]


# Rule Version Endpoint


@router.get("/{rule_id}/versions/{version_number}", response_model=RuleVersionResponse)
async def get_rule_version(
    rule_id: UUID,
    version_number: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get a specific version of a rule by version number."""
    # Verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if rule_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    # Get the specific version
    version_result = await db.execute(
        select(RuleVersion).where(
            RuleVersion.rule_id == rule_id,
            RuleVersion.version_number == version_number,
        )
    )
    version = version_result.scalar_one_or_none()

    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version {version_number} not found for this rule"
        )

    return RuleVersionResponse(
        id=version.id,
        version_number=version.version_number,
        yaml_content=version.yaml_content,
        created_at=version.created_at,
        change_reason=version.change_reason,
        changed_by=version.changed_by,
    )
