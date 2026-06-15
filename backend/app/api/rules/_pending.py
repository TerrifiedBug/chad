"""Transitional module: rules routes not yet extracted into a dedicated
sub-router (plan 010 step 3). Migrated out one group at a time; removed when
empty.
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
from app.api.rules._shared import (
    DeploymentEligibilityRequest,
    DeploymentEligibilityResponse,
    IneligibleRule,
    _evaluate_rule_eligibility,
    build_field_mapping_info,
)
from app.core.config import settings as app_settings
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
    DeployPreviewEligibility,
    DeployPreviewResponse,
    DeployPreviewValidation,
    HistoricalTestRequest,
    HistoricalTestResponse,
    LogMatchResult,
    RuleCreate,
    RuleDetailResponse,
    RuleResponse,
    RuleTestRequest,
    RuleTestResponse,
    RuleUpdate,
    RuleValidateRequest,
    RuleValidateResponse,
    ValidationErrorItem,
)
from app.services.attack_sync import update_rule_attack_mappings
from app.services.audit import audit_log
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.rule_testing import run_historical_test
from app.services.settings import get_setting, set_setting
from app.services.sigma import sigma_service
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
    from app.services.opensearch import get_index_fields

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

    await audit_log(db, current_user.id, "rule.create", "rule", str(rule.id), {"title": rule.title}, ip_address=get_client_ip(request))
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
                    detail="Change reason is required when updating rules. Please explain why you're making this change.",
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

    await audit_log(db, current_user.id, "rule.update", "rule", str(rule.id), {"title": rule.title}, ip_address=get_client_ip(request))
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
    await audit_log(db, current_user.id, "rule.delete", "rule", str(rule_id), audit_details, ip_address=get_client_ip(request))

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


@router.post("/validate", response_model=RuleValidateResponse)
async def validate_rule(
    request: RuleValidateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    opensearch: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Validate a Sigma rule YAML.

    Checks:
    1. YAML syntax
    2. Sigma schema (required fields)
    3. Field existence in target index (if index_pattern_id provided)
    """
    # Parse and validate the rule
    result = sigma_service.translate_and_validate(request.yaml_content)

    if not result.success:
        return RuleValidateResponse(
            valid=False,
            errors=[
                ValidationErrorItem(
                    type=e.type,
                    message=e.message,
                    line=e.line,
                    field=e.field,
                )
                for e in (result.errors or [])
            ],
        )

    # If index_pattern_id provided, validate fields exist in OpenSearch
    if request.index_pattern_id:
        # Get the index pattern
        pattern_result = await db.execute(
            select(IndexPattern).where(IndexPattern.id == request.index_pattern_id)
        )
        index_pattern = pattern_result.scalar_one_or_none()

        if index_pattern is None:
            return RuleValidateResponse(
                valid=False,
                errors=[
                    ValidationErrorItem(
                        type="field",
                        message="Index pattern not found",
                    )
                ],
            )

        # Get fields from OpenSearch index (include .keyword for field mapping validation)
        index_fields = get_index_fields(opensearch, index_pattern.pattern, include_multi_fields=True)

        # Get field mappings for this index pattern
        sigma_fields = list(result.fields or set())
        field_mappings = await resolve_mappings(db, sigma_fields, request.index_pattern_id)

        # Auto-correct field mappings that point to text fields
        from app.services.field_type_detector import auto_correct_field_mapping

        corrected_mappings = {}
        for sigma_field, target_field in field_mappings.items():
            if target_field:  # Only auto-correct if there's a mapping
                corrected_field, was_corrected = auto_correct_field_mapping(
                    opensearch, index_pattern.pattern, target_field
                )
                corrected_mappings[sigma_field] = corrected_field

                if was_corrected:
                    import logging
                    logging.getLogger(__name__).info(
                        f"Auto-corrected field mapping in validation: '{sigma_field}' -> '{target_field}' to '{corrected_field}'"
                    )
            else:
                corrected_mappings[sigma_field] = None

        field_mappings = corrected_mappings

        # Check if all rule fields exist in index OR have a valid mapping
        missing_fields = []
        for field in sigma_fields:
            # Check if field exists directly in index
            if field in index_fields:
                continue
            # Check if field has a mapping to a field that exists in index
            mapped_field = field_mappings.get(field)
            if mapped_field and mapped_field in index_fields:
                continue
            # Field is unmapped or mapped to non-existent field
            missing_fields.append(field)

        if missing_fields:
            field_mapping_info = build_field_mapping_info(sigma_fields, field_mappings, index_fields)
            return RuleValidateResponse(
                valid=False,
                errors=[
                    ValidationErrorItem(
                        type="field",
                        field=field,
                        message=f"Field '{field}' not found in index '{index_pattern.pattern}'",
                    )
                    for field in missing_fields
                ],
                fields=list(result.fields or set()),
                field_mappings=field_mapping_info,
            )

        field_mapping_info = build_field_mapping_info(sigma_fields, field_mappings, index_fields)

        # Re-translate with field mappings applied so query preview shows mapped fields
        field_mappings_dict = {k: v for k, v in field_mappings.items() if v is not None}
        if field_mappings_dict:
            mapped_result = sigma_service.translate_with_mappings(
                request.yaml_content, field_mappings_dict
            )
            query_to_return = mapped_result.query if mapped_result.success else result.query
        else:
            query_to_return = result.query

        return RuleValidateResponse(
            valid=True,
            opensearch_query=query_to_return,
            fields=list(result.fields or set()),
            field_mappings=field_mapping_info,
        )

    # No index pattern provided - just validate syntax
    return RuleValidateResponse(
        valid=True,
        opensearch_query=result.query,
        fields=list(result.fields or set()),
    )


@router.post("/check-deployment-eligibility", response_model=DeploymentEligibilityResponse)
async def check_deployment_eligibility(
    request: DeploymentEligibilityRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    opensearch: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Check which rules can be deployed (have all fields mapped)."""
    eligible: list[UUID] = []
    ineligible: list[IneligibleRule] = []

    for rule_id in request.rule_ids:
        rule = await db.get(Rule, rule_id)
        if not rule:
            ineligible.append(IneligibleRule(id=rule_id, reason="Rule not found"))
            continue

        index_pattern = await db.get(IndexPattern, rule.index_pattern_id)
        is_eligible, reason, _ = await _evaluate_rule_eligibility(
            db, rule, index_pattern, opensearch
        )
        if is_eligible:
            eligible.append(rule_id)
        else:
            ineligible.append(IneligibleRule(id=rule_id, reason=reason or "Ineligible"))

    return DeploymentEligibilityResponse(eligible=eligible, ineligible=ineligible)


@router.get("/{rule_id}/deploy-preview", response_model=DeployPreviewResponse)
async def deploy_preview(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    _: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Read-only deploy preview consolidating eligibility + validate + the
    current-vs-proposed DSL diff for a single rule.

    Mutates nothing. ``current_deployed_query`` is the live percolator query
    (inner query) for push-mode deployed rules, or null when the rule is
    undeployed, pull-mode, or absent from the percolator. ``proposed_query`` is
    the freshly translated current YAML with field mappings applied.
    """
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    index_pattern = rule.index_pattern

    # --- Validation (translate current YAML) ---
    validation_result = sigma_service.translate_and_validate(rule.yaml_content)
    validation = DeployPreviewValidation(
        success=validation_result.success,
        errors=[
            ValidationErrorItem(type=e.type, message=e.message, line=e.line, field=e.field)
            for e in (validation_result.errors or [])
        ],
    )

    # --- Eligibility (reuse the shared single-rule field-mapping check) ---
    is_eligible, reason, unmapped = await _evaluate_rule_eligibility(
        db, rule, index_pattern, os_client
    )
    eligibility = DeployPreviewEligibility(
        eligible=is_eligible, reason=reason, unmapped_fields=unmapped
    )

    # --- Proposed query (translate with resolved mappings -> inner query) ---
    proposed_query: dict | None = None
    if validation_result.success:
        sigma_fields = list(validation_result.fields or set())
        field_mappings_dict: dict[str, str] = {}
        if sigma_fields and rule.index_pattern_id:
            resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
            field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}
        translation = sigma_service.translate_with_mappings(
            rule.yaml_content, field_mappings_dict or None
        )
        if translation.success and translation.query:
            # Sigma returns {"query": {...}}; expose the inner query for the diff.
            proposed_query = translation.query.get("query", translation.query)

    # --- Current deployed query (push mode only; never raise on OS errors) ---
    current_deployed_query: dict | None = None
    use_percolator = (
        os_client is not None
        and not app_settings.is_pull_only
        and index_pattern is not None
        and index_pattern.mode == "push"
        and rule.deployed_at is not None
    )
    if use_percolator:
        try:
            percolator = PercolatorService(os_client)
            percolator_index = percolator.get_percolator_index_name(index_pattern.pattern)
            deployed_doc = percolator.get_deployed_rule(percolator_index, str(rule.id))
            if deployed_doc:
                # The stored doc holds the inner query directly under "query".
                current_deployed_query = deployed_doc.get("query")
        except Exception:
            # Read-only preview must never leak an OpenSearch error path.
            current_deployed_query = None

    current_version = rule.versions[0].version_number if rule.versions else 1
    needs_redeploy = (
        rule.deployed_at is not None
        and rule.deployed_version is not None
        and rule.deployed_version != current_version
    )

    return DeployPreviewResponse(
        rule_id=rule.id,
        current_deployed_query=current_deployed_query,
        proposed_query=proposed_query,
        validation=validation,
        eligibility=eligibility,
        needs_redeploy=needs_redeploy,
        deployed_version=rule.deployed_version,
        current_version=current_version,
        dry_run=None,
    )


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    request: RuleTestRequest,
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Test a Sigma rule against sample log data using OpenSearch percolate.

    Requires OpenSearch connection for accurate matching.
    """
    import uuid as uuid_module

    # Parse and translate the rule, applying field mappings if index pattern provided
    result = sigma_service.translate_and_validate(request.yaml_content)

    if not result.success:
        return RuleTestResponse(
            matches=[],
            errors=[
                ValidationErrorItem(
                    type=e.type,
                    message=e.message,
                    line=e.line,
                    field=e.field,
                )
                for e in (result.errors or [])
            ],
        )

    # Re-translate with field mappings so the query uses actual log field names
    if request.index_pattern_id and result.fields:
        sigma_fields = list(result.fields)
        field_mappings = await resolve_mappings(
            db, sigma_fields, request.index_pattern_id
        )
        field_mappings_dict = {
            k: v for k, v in field_mappings.items() if v is not None
        }
        if field_mappings_dict:
            mapped_result = sigma_service.translate_with_mappings(
                request.yaml_content, field_mappings_dict
            )
            if mapped_result.success and mapped_result.query:
                result = mapped_result

    if os_client is None:
        return RuleTestResponse(
            matches=[],
            errors=[
                ValidationErrorItem(
                    type="config",
                    message="OpenSearch not configured. Cannot test rules without OpenSearch connection.",
                )
            ],
        )

    # Use a unique test percolator index per request (cleaned up after)
    test_index = f"chad-test-{uuid_module.uuid4()}"

    # Create test index with percolator mapping
    # map_unmapped_fields_as_text allows queries to reference fields not in mapping
    try:
        # Build base mapping for test index
        test_mapping = {
            "settings": {
                "index.percolator.map_unmapped_fields_as_text": True,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "query": {"type": "percolator"},
                }
            }
        }

        # Copy field mappings from source index if index_pattern_id provided
        # This matches production behavior in percolator.py:86-93
        if request.index_pattern_id:
            try:
                ip_result = await db.execute(
                    select(IndexPattern).where(IndexPattern.id == request.index_pattern_id)
                )
                index_pattern = ip_result.scalar_one_or_none()
                if index_pattern:
                    source_mappings = os_client.indices.get_mapping(index=index_pattern.pattern)
                    if source_mappings:
                        first_index = list(source_mappings.keys())[0]
                        source_props = source_mappings[first_index].get("mappings", {}).get("properties", {})
                        test_mapping["mappings"]["properties"].update(source_props)
            except Exception:
                pass  # Fall back to dynamic mapping if source fetch fails

        os_client.indices.create(index=test_index, body=test_mapping)
    except Exception as e:
        return RuleTestResponse(
            matches=[],
            errors=[
                ValidationErrorItem(
                    type="opensearch",
                    message=f"Failed to create test index: {str(e)}",
                )
            ],
        )

    # Index the test query
    temp_id = "test-query"
    percolator_query = result.query.get("query", result.query)

    try:
        os_client.index(
            index=test_index,
            id=temp_id,
            body={"query": percolator_query},
            refresh=True,
        )
    except Exception as e:
        return RuleTestResponse(
            matches=[],
            errors=[
                ValidationErrorItem(
                    type="opensearch",
                    message=f"Failed to index test query: {str(e)}",
                )
            ],
        )

    try:
        # Test each sample log against the percolator
        matches = []
        for idx, log in enumerate(request.sample_logs):
            # Unwrap OpenSearch hit envelopes (users may paste raw hits)
            if "_source" in log and isinstance(log["_source"], dict):
                log = log["_source"]
            try:
                response = os_client.search(
                    index=test_index,
                    body={
                        "query": {
                            "percolate": {
                                "field": "query",
                                "document": log,
                            }
                        }
                    }
                )
                matched = response["hits"]["total"]["value"] > 0
            except Exception:
                # If percolation fails for this log, mark as not matched
                matched = False

            matches.append(LogMatchResult(log_index=idx, matched=matched))

        return RuleTestResponse(
            matches=matches,
            opensearch_query=result.query,
        )

    finally:
        # Always clean up temporary test index
        try:
            os_client.indices.delete(index=test_index, ignore=[404])
        except Exception:
            pass  # Best effort cleanup


@router.post("/{rule_id}/test-historical", response_model=HistoricalTestResponse)
async def test_rule_historical(
    rule_id: UUID,
    request: HistoricalTestRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Test a rule against historical log data.

    This is a "dry-run" feature that shows what would have matched
    without creating any alerts. Useful for:
    - Validating a new rule before deployment
    - Understanding rule match rates
    - Identifying false positives

    The query is executed against the rule's associated index pattern
    with a time range filter applied.

    Args:
        rule_id: ID of the rule to test
        start_date: Start of time range to search
        end_date: End of time range to search
        limit: Maximum matches to return (1-1000, default 500)

    Returns:
        Total documents scanned, total matches, sample match documents,
        and whether results were truncated.
    """
    # Validate that end_date > start_date
    if request.end_date <= request.start_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_date must be greater than start_date",
        )

    result = await run_historical_test(
        db=db,
        os_client=os_client,
        rule_id=rule_id,
        start_date=request.start_date,
        end_date=request.end_date,
        limit=request.limit,
    )

    # If there's an error from the service, return it as HTTP error
    if result.error:
        # Determine appropriate status code based on error type
        if "not found" in result.error.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=result.error,
            )
        elif "translate" in result.error.lower() or "no query" in result.error.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error,
            )
        else:
            # OpenSearch errors or other issues
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error,
            )

    return HistoricalTestResponse(
        total_scanned=result.total_scanned,
        total_matches=result.total_matches,
        matches=result.matches,
        truncated=result.truncated,
        query_executed=result.query_executed,
    )




# Bulk Operations Endpoints (must be before single-rule endpoints to avoid route conflicts)


