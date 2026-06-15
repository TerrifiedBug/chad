"""Rule CRUD sub-router: list, index-fields, check-title, settings, create,
get, update, and delete rules.
"""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_current_user,
    get_opensearch_client,
    get_opensearch_client_optional,
    require_permission_dep,
)
from app.db.session import get_db
from app.models.correlation_rule import CorrelationRule
from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestItem,
    DeploymentRequestStatus,
)
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.user import User
from app.schemas.rule import (
    RuleCreate,
    RuleDetailResponse,
    RuleResponse,
    RuleUpdate,
)
from app.services.attack_sync import update_rule_attack_mappings
from app.services.audit import audit_log
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.settings import get_setting, set_setting
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    status_filter: RuleStatus | None = None,
    source_filter: RuleSource | None = None,
    skip: int = 0,
    limit: int = 100,
):
    # Load rules with versions and version authors to get last edited by
    query = (
        select(Rule)
        .options(
            selectinload(Rule.versions).selectinload(RuleVersion.author)
        )
        .order_by(Rule.updated_at.desc())
        .offset(skip)
        .limit(limit)
    )
    if status_filter:
        query = query.where(Rule.status == status_filter)
    if source_filter:
        query = query.where(Rule.source == source_filter)
    # Resource-scoped RBAC: non-admins see only their team's + global rules.
    from app.services.team_scope import apply_team_scope
    query = apply_team_scope(query, Rule, current_user)
    result = await db.execute(query)
    rules = result.scalars().all()

    # One query for the whole page: which of these rules have an OPEN (pending)
    # DeploymentRequest? Avoids an N+1 lookup per row for the "Pending approval"
    # badge.
    rule_ids = [rule.id for rule in rules]
    open_request_rule_ids: set[UUID] = set()
    if rule_ids:
        open_rows = await db.execute(
            select(DeploymentRequestItem.rule_id)
            .join(DeploymentRequest, DeploymentRequestItem.request_id == DeploymentRequest.id)
            .where(
                DeploymentRequestItem.rule_id.in_(rule_ids),
                DeploymentRequest.status == DeploymentRequestStatus.PENDING.value,
            )
        )
        open_request_rule_ids = {rid for (rid,) in open_rows.all() if rid is not None}

    # Build response with last_edited_by and needs_redeploy
    responses = []
    for rule in rules:
        # Calculate current version and needs_redeploy
        current_version = rule.versions[0].version_number if rule.versions else 1
        needs_redeploy = (
            rule.deployed_at is not None and
            rule.deployed_version is not None and
            rule.deployed_version != current_version
        )

        rule_dict = {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "yaml_content": rule.yaml_content,
            "severity": rule.severity,
            "status": rule.status,
            "snooze_until": rule.snooze_until,
            "snooze_indefinite": rule.snooze_indefinite,
            "created_by": rule.created_by,
            "created_at": rule.created_at,
            "updated_at": rule.updated_at,
            "deployed_at": rule.deployed_at,
            "deployed_version": rule.deployed_version,
            "current_version": current_version,
            "needs_redeploy": needs_redeploy,
            "has_open_request": rule.id in open_request_rule_ids,
            "index_pattern_id": rule.index_pattern_id,
            "last_edited_by": None,
            "source": rule.source,
            "sigmahq_path": rule.sigmahq_path,
            "threshold_enabled": rule.threshold_enabled,
            "threshold_count": rule.threshold_count,
            "threshold_window_minutes": rule.threshold_window_minutes,
            "threshold_group_by": rule.threshold_group_by,
        }
        # Get the latest version's author (versions are already sorted desc by version_number)
        if rule.versions:
            latest_version = rule.versions[0]
            if latest_version.author:
                rule_dict["last_edited_by"] = latest_version.author.email

        responses.append(rule_dict)

    return responses


@router.get("/index-fields/{index_pattern_id}")
async def get_index_pattern_fields(
    index_pattern_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Get all fields from an index pattern for the exceptions dropdown.

    Uses the same pattern as field mappings - fetches actual fields
    from OpenSearch index mappings.
    """

    # Get index pattern
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.id == index_pattern_id)
    )
    index_pattern = result.scalar_one_or_none()

    if not index_pattern:
        raise HTTPException(status_code=404, detail="Index pattern not found")

    # Get fields from OpenSearch for the exceptions dropdown
    # Exclude .keyword multi-fields since exceptions match against actual log data
    try:
        fields = list(get_index_fields(os_client, index_pattern.pattern, include_multi_fields=False))
        return {"fields": sorted(fields)}  # Sort alphabetically for UX
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to get index fields: {e}"
        )


class TitleCheckRequest(BaseModel):
    title: str
    exclude_id: str | None = None  # Exclude this rule ID when checking (for updates)


class TitleCheckResponse(BaseModel):
    available: bool
    message: str | None = None


@router.post("/check-title", response_model=TitleCheckResponse)
async def check_title_availability(
    data: TitleCheckRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Check if a rule title is available (not already in use)."""
    query = select(Rule).where(Rule.title == data.title)

    # If editing an existing rule, exclude it from the check
    if data.exclude_id:
        query = query.where(Rule.id != UUID(data.exclude_id))

    result = await db.execute(query)
    existing = result.scalar_one_or_none()

    if existing:
        return TitleCheckResponse(
            available=False,
            message=f"A rule with the title '{data.title}' already exists."
        )

    return TitleCheckResponse(available=True)


# --- Rule Settings ---

DEFAULT_DEPLOYMENT_ALERT_THRESHOLD = 100


class RuleSettingsResponse(BaseModel):
    deployment_alert_threshold: int


class RuleSettingsUpdate(BaseModel):
    deployment_alert_threshold: int = Field(default=100, ge=1, le=100000)


@router.get("/settings", response_model=RuleSettingsResponse)
async def get_rule_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Get rule-related settings."""
    setting = await get_setting(db, "rule_settings")
    data = setting or {}
    return RuleSettingsResponse(
        deployment_alert_threshold=data.get("deployment_alert_threshold", DEFAULT_DEPLOYMENT_ALERT_THRESHOLD),
    )


@router.put("/settings", response_model=RuleSettingsResponse)
async def update_rule_settings(
    data: RuleSettingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Update rule-related settings."""
    current = await get_setting(db, "rule_settings")
    settings_data = current or {}
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        settings_data[key] = value
    await set_setting(db, "rule_settings", settings_data)
    return RuleSettingsResponse(
        deployment_alert_threshold=settings_data.get("deployment_alert_threshold", DEFAULT_DEPLOYMENT_ALERT_THRESHOLD),
    )


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: Request,
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    rule = Rule(
        title=rule_data.title,
        description=rule_data.description,
        yaml_content=rule_data.yaml_content,
        severity=rule_data.severity,
        status=rule_data.status,
        index_pattern_id=rule_data.index_pattern_id,
        created_by=current_user.id,
        team_id=current_user.team_id,  # owned by the creator's team (None = global)
        threshold_enabled=rule_data.threshold_enabled,
        threshold_count=rule_data.threshold_count,
        threshold_window_minutes=rule_data.threshold_window_minutes,
        threshold_group_by=rule_data.threshold_group_by,
    )
    db.add(rule)

    try:
        await db.flush()  # Flush to get the rule.id
    except IntegrityError as e:
        await db.rollback()
        if "uq_rules_title" in str(e.orig) or "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A rule with the title '{rule_data.title}' already exists. Please choose a different title.",
            )
        raise

    # Create initial version
    version = RuleVersion(
        rule_id=rule.id,
        version_number=1,
        yaml_content=rule_data.yaml_content,
        changed_by=current_user.id,
        change_reason="Initial version",
        created_at=datetime.now(UTC),
    )
    db.add(version)

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        if "uq_rules_title" in str(e.orig) or "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A rule with the title '{rule_data.title}' already exists. Please choose a different title.",
            )
        raise

    await db.refresh(rule)

    # Update ATT&CK mappings from tags
    try:
        parsed = yaml.safe_load(rule_data.yaml_content)
        if parsed and isinstance(parsed, dict):
            tags = parsed.get("tags", [])
            await update_rule_attack_mappings(db, rule.id, tags)
            await db.commit()
    except Exception:
        pass  # Don't fail rule creation if tag parsing fails

    await audit_log(
        db, current_user.id, "rule.create", "rule", str(rule.id),
        {"title": rule.title}, ip_address=get_client_ip(request),
    )
    await db.commit()
    return rule


@router.get("/{rule_id}", response_model=RuleDetailResponse)
async def get_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    # First get the rule
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Explicitly query versions in descending order to ensure fresh data
    versions_result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.rule_id == rule_id)
        .options(selectinload(RuleVersion.author))
        .order_by(RuleVersion.version_number.desc())
    )
    versions = versions_result.scalars().all()

    # Compute current_version and needs_redeploy
    current_version = versions[0].version_number if versions else 1
    needs_redeploy = (
        rule.deployed_at is not None
        and rule.deployed_version is not None
        and rule.deployed_version != current_version
    )

    # Get last editor email
    last_edited_by = None
    if versions:
        last_version = versions[0]
        if last_version.author:
            last_edited_by = last_version.author.email

    # Does this rule have an OPEN (pending) DeploymentRequest? (Pending badge.)
    open_request = await db.execute(
        select(DeploymentRequestItem.id)
        .join(DeploymentRequest, DeploymentRequestItem.request_id == DeploymentRequest.id)
        .where(
            DeploymentRequestItem.rule_id == rule_id,
            DeploymentRequest.status == DeploymentRequestStatus.PENDING.value,
        )
        .limit(1)
    )
    has_open_request = open_request.scalar_one_or_none() is not None

    return RuleDetailResponse(
        id=rule.id,
        title=rule.title,
        description=rule.description,
        yaml_content=rule.yaml_content,
        severity=rule.severity,
        index_pattern_id=rule.index_pattern_id,
        status=rule.status,
        snooze_until=rule.snooze_until,
        snooze_indefinite=rule.snooze_indefinite,
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        deployed_at=rule.deployed_at,
        deployed_version=rule.deployed_version,
        current_version=current_version,
        needs_redeploy=needs_redeploy,
        has_open_request=has_open_request,
        last_edited_by=last_edited_by,
        source=rule.source,
        sigmahq_path=rule.sigmahq_path,
        index_pattern=rule.index_pattern,
        versions=versions,
        threshold_enabled=rule.threshold_enabled,
        threshold_count=rule.threshold_count,
        threshold_window_minutes=rule.threshold_window_minutes,
        threshold_group_by=rule.threshold_group_by,
    )


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_data: RuleUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    update_data = rule_data.model_dump(exclude_unset=True)
    old_status = rule.status

    # Check if mandatory comments enabled
    from app.models.notification_settings import NotificationSettings

    settings_result = await db.execute(select(NotificationSettings).limit(1))
    settings = settings_result.scalar_one_or_none()

    if settings and settings.mandatory_rule_comments:
        # Check if rule is deployed and setting is deployed-only
        is_deployed = rule.status == RuleStatus.DEPLOYED
        requires_comment = not settings.mandatory_comments_deployed_only or is_deployed

        # If yaml_content is being updated, check for change_reason
        if requires_comment and "yaml_content" in update_data:
            if not update_data.get("change_reason") or not update_data.get("change_reason", "").strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Change reason is required when updating rules. "
                        "Please explain why you're making this change."
                    ),
                )

    # If yaml_content changed, create new version
    if "yaml_content" in update_data and update_data["yaml_content"] != rule.yaml_content:
        # Get latest version number
        version_result = await db.execute(
            select(RuleVersion)
            .where(RuleVersion.rule_id == rule_id)
            .order_by(RuleVersion.version_number.desc())
            .limit(1)
        )
        latest_version = version_result.scalar_one_or_none()
        next_version = (latest_version.version_number + 1) if latest_version else 1

        new_version = RuleVersion(
            rule_id=rule_id,
            version_number=next_version,
            yaml_content=update_data["yaml_content"],
            changed_by=current_user.id,
            change_reason=update_data.get("change_reason", "Rule updated"),
            created_at=datetime.now(UTC),
        )
        db.add(new_version)

        # Audit log for rule update
        client_ip = request.client.host if request.client else None
        await audit_log(
            db,
            current_user.id,
            "rule_updated",
            "rule",
            str(rule_id),
            {
                "rule_title": rule.title,
                "version_number": next_version,
                "change_reason": update_data.get("change_reason", "Rule updated"),
            },
            ip_address=client_ip,
        )

    for field, value in update_data.items():
        if field != "change_reason":  # Skip - belongs to RuleVersion, not Rule
            setattr(rule, field, value)

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        if "uq_rules_title" in str(e.orig) or "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A rule with the title '{rule.title}' already exists. Please choose a different title.",
            )
        raise

    await db.refresh(rule)

    # Update ATT&CK mappings if yaml_content changed
    if "yaml_content" in update_data:
        try:
            parsed = yaml.safe_load(update_data["yaml_content"])
            if parsed and isinstance(parsed, dict):
                tags = parsed.get("tags", [])
                await update_rule_attack_mappings(db, rule.id, tags)
                await db.commit()
        except Exception:
            pass  # Don't fail rule update if tag parsing fails

    await audit_log(
        db, current_user.id, "rule.update", "rule", str(rule.id),
        {"title": rule.title}, ip_address=get_client_ip(request),
    )
    await db.commit()

    # If status changed and rule is deployed, sync to OpenSearch
    if "status" in update_data and rule.deployed_at is not None and os_client is not None:
        new_status = update_data["status"]
        if new_status != old_status:
            percolator = PercolatorService(os_client)
            percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
            percolator.update_rule_status(
                percolator_index,
                str(rule.id),
                enabled=(new_status == RuleStatus.DEPLOYED),
            )

    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    change_reason: str | None = Body(None, min_length=1, max_length=10000, embed=True),
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Capture details before delete
    audit_details = {"title": rule.title}
    if change_reason:
        audit_details["change_reason"] = change_reason
    await audit_log(
        db, current_user.id, "rule.delete", "rule", str(rule_id),
        audit_details, ip_address=get_client_ip(request),
    )

    # Undeploy any correlation rules that reference this rule
    corr_result = await db.execute(
        select(CorrelationRule).where(
            or_(CorrelationRule.rule_a_id == rule_id, CorrelationRule.rule_b_id == rule_id),
            CorrelationRule.deployed_at.isnot(None),
        )
    )
    for corr_rule in corr_result.scalars().all():
        corr_rule.deployed_at = None
        corr_rule.deployed_version = None

    await db.delete(rule)
    await db.commit()


