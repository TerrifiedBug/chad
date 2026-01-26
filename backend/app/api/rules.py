from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_opensearch_client, get_opensearch_client_optional, require_permission_dep
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.rule_comment import RuleComment
from app.models.rule_exception import RuleException
from app.models.user import User
from app.schemas.bulk import BulkOperationRequest, BulkOperationResult
from app.schemas.rule import (
    FieldMappingInfo,
    HistoricalTestRequest,
    HistoricalTestResponse,
    LogMatchResult,
    RuleCreate,
    RuleDeployResponse,
    RuleDetailResponse,
    RuleResponse,
    RuleRollbackResponse,
    RuleTestRequest,
    RuleTestResponse,
    RuleUndeployResponse,
    RuleUpdate,
    RuleValidateRequest,
    RuleValidateResponse,
    RuleVersionResponse,
    UnmappedFieldsError,
    ValidationErrorItem,
)
from app.schemas.rule_exception import (
    RuleExceptionCreate,
    RuleExceptionResponse,
    RuleExceptionUpdate,
)
from app.services.attack_sync import update_rule_attack_mappings
from app.services.audit import audit_log
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.rule_testing import run_historical_test
from app.services.sigma import sigma_service
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


class SnoozeRequest(BaseModel):
    hours: int | None = Field(default=None, ge=1, le=168)  # None allowed if indefinite
    indefinite: bool = False


class DeploymentEligibilityRequest(BaseModel):
    rule_ids: list[UUID]


class IneligibleRule(BaseModel):
    id: UUID
    reason: str


class DeploymentEligibilityResponse(BaseModel):
    eligible: list[UUID]
    ineligible: list[IneligibleRule]


class RuleCommentCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)


class RuleCommentResponse(BaseModel):
    id: str
    rule_id: str
    user_id: str | None
    user_email: str | None
    content: str
    created_at: datetime


class ActivityItem(BaseModel):
    """Activity timeline item for a rule."""

    type: str  # 'version', 'deploy', 'undeploy', 'comment'
    timestamp: datetime
    user_email: str | None
    data: dict


def build_field_mapping_info(
    sigma_fields: list[str],
    field_mappings: dict[str, str],
    index_fields: set[str],
) -> list[FieldMappingInfo]:
    """Build field mapping info for all sigma fields with consistent logic."""
    result = []
    for field in sigma_fields:
        if field in field_mappings and field_mappings[field] in index_fields:
            result.append(FieldMappingInfo(sigma_field=field, target_field=field_mappings[field]))
        elif field in index_fields:
            result.append(FieldMappingInfo(sigma_field=field, target_field=field))
        else:
            result.append(FieldMappingInfo(sigma_field=field, target_field=None))
    return result


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
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
    result = await db.execute(query)
    rules = result.scalars().all()

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
        threshold_enabled=rule_data.threshold_enabled,
        threshold_count=rule_data.threshold_count,
        threshold_window_minutes=rule_data.threshold_window_minutes,
        threshold_group_by=rule_data.threshold_group_by,
    )
    db.add(rule)
    await db.flush()  # Flush to get the rule.id

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

    await db.commit()
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

    await db.commit()
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
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Capture details before delete
    await audit_log(db, current_user.id, "rule.delete", "rule", str(rule_id), {"title": rule.title}, ip_address=get_client_ip(request))
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

        # Get fields from OpenSearch index
        index_fields = get_index_fields(opensearch, index_pattern.pattern)

        # Get field mappings for this index pattern
        sigma_fields = list(result.fields or set())
        field_mappings = await resolve_mappings(db, sigma_fields, request.index_pattern_id)

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

        # Check field mappings
        index_pattern = await db.get(IndexPattern, rule.index_pattern_id)
        if not index_pattern:
            ineligible.append(IneligibleRule(id=rule_id, reason="Index pattern not found"))
            continue

        try:
            # Get detected fields from rule
            result = sigma_service.translate_and_validate(rule.yaml_content)
            if not result.success:
                errors_str = ", ".join(e.message for e in (result.errors or []))
                ineligible.append(IneligibleRule(id=rule_id, reason=f"Invalid rule: {errors_str}"))
                continue

            detected_fields = list(result.fields or set())

            if not detected_fields:
                # No fields to check, rule is eligible
                eligible.append(rule_id)
                continue

            # Get fields from the OpenSearch index
            try:
                if opensearch:
                    index_fields = set(get_index_fields(opensearch, index_pattern.pattern))
                else:
                    index_fields = set()
            except Exception:
                index_fields = set()

            # Check mappings - resolve field mappings for this rule
            mappings = await resolve_mappings(db, detected_fields, rule.index_pattern_id)

            # Find unmapped fields (fields that don't exist in index AND have no valid mapping)
            unmapped = []
            for field in detected_fields:
                # Field is OK if it has a mapping AND the target exists, OR it exists directly
                if field in mappings and mappings[field] is not None:
                    target_field = mappings[field]
                    if target_field in index_fields:
                        continue  # Has a valid mapping to an existing field
                    # Mapping target doesn't exist - still unmapped
                elif field in index_fields:
                    continue  # Exists directly in index
                unmapped.append(field)

            if unmapped:
                ineligible.append(IneligibleRule(
                    id=rule_id,
                    reason=f"Unmapped fields: {', '.join(unmapped)}"
                ))
            else:
                eligible.append(rule_id)
        except Exception as e:
            ineligible.append(IneligibleRule(id=rule_id, reason=str(e)))

    return DeploymentEligibilityResponse(eligible=eligible, ineligible=ineligible)


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    request: RuleTestRequest,
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Test a Sigma rule against sample log data using OpenSearch percolate.

    Requires OpenSearch connection for accurate matching.
    """
    import uuid as uuid_module

    # Parse and translate the rule
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
        os_client.indices.create(
            index=test_index,
            body={
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
        )
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


@router.post("/{rule_id}/deploy", response_model=RuleDeployResponse, responses={400: {"model": UnmappedFieldsError}})
async def deploy_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """
    Deploy a rule to its OpenSearch percolator index.

    Process:
    1. Fetch rule and index pattern from DB
    2. Parse Sigma YAML with pySigma
    3. Check fields exist in index OR have field mappings configured
    4. Resolve field mappings (Sigma fields → log fields)
    5. Translate to OpenSearch query with field mappings applied
    6. Ensure percolator index exists
    7. Index the percolator document
    8. Update rule.deployed_at timestamp

    Returns 400 with unmapped_fields if Sigma fields don't exist in index
    and don't have mappings configured.
    """
    # Fetch rule with index pattern
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # First validate the rule
    validation = sigma_service.translate_and_validate(rule.yaml_content)
    if not validation.success:
        errors_str = ", ".join(e.message for e in (validation.errors or []))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to translate rule: {errors_str}",
        )

    # Extract fields and resolve mappings
    sigma_fields = list(validation.fields or set())
    field_mappings_dict: dict[str, str] = {}

    if sigma_fields and rule.index_pattern_id:
        # Resolve field mappings (per-index overrides global)
        resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
        # Build dict of only mapped fields (exclude None values)
        field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

        # Get fields from the OpenSearch index
        try:
            index_fields = set(get_index_fields(os_client, rule.index_pattern.pattern))
        except Exception:
            index_fields = set()

        # Check for unmapped fields that don't exist in the index
        unmapped_fields = []
        for sigma_field in sigma_fields:
            # Field is OK if it has a mapping AND the target exists, OR it exists directly
            if sigma_field in field_mappings_dict:
                target_field = field_mappings_dict[sigma_field]
                if target_field in index_fields:
                    continue  # Has a valid mapping to an existing field
                # Mapping target doesn't exist - still unmapped
            elif sigma_field in index_fields:
                continue  # Exists directly in index
            unmapped_fields.append(sigma_field)

        if unmapped_fields:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=UnmappedFieldsError(
                    message=f"The following fields are not found in the index and have no mappings configured: {', '.join(unmapped_fields)}",
                    unmapped_fields=unmapped_fields,
                    index_pattern_id=rule.index_pattern_id,
                ).model_dump(mode="json"),
            )

    # Translate rule with field mappings applied
    translation = sigma_service.translate_with_mappings(
        rule.yaml_content, field_mappings_dict if field_mappings_dict else None
    )
    if not translation.success:
        errors_str = ", ".join(e.message for e in (translation.errors or []))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to translate rule: {errors_str}",
        )

    # Deploy to percolator
    percolator = PercolatorService(os_client)
    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)

    # Ensure the percolator index exists (copy mappings from source index)
    percolator.ensure_percolator_index(percolator_index, rule.index_pattern.pattern)

    # Extract rule metadata from YAML for the percolator doc
    parsed_rule = yaml.safe_load(rule.yaml_content)
    tags = parsed_rule.get("tags", [])

    # Deploy the rule - extract inner query for percolator
    # Sigma returns {"query": {"query_string": ...}}, percolator needs {"query_string": ...}
    percolator_query = translation.query.get("query", translation.query)

    percolator.deploy_rule(
        percolator_index=percolator_index,
        rule_id=str(rule.id),
        query=percolator_query,
        title=rule.title,
        severity=rule.severity,
        tags=tags,
        enabled=(rule.status == RuleStatus.DEPLOYED),
    )

    # Update rule deployment tracking
    now = datetime.now(UTC)
    current_version = rule.versions[0].version_number if rule.versions else 1
    rule.deployed_at = now
    rule.deployed_version = current_version
    # Set status to DEPLOYED (unless already snoozed)
    if rule.status != RuleStatus.SNOOZED:
        rule.status = RuleStatus.DEPLOYED

    await db.commit()
    await db.refresh(rule)
    await audit_log(db, current_user.id, "rule.deploy", "rule", str(rule.id), {"title": rule.title, "percolator_index": percolator_index}, ip_address=get_client_ip(request))
    await db.commit()

    return RuleDeployResponse(
        success=True,
        rule_id=rule.id,
        percolator_index=percolator_index,
        deployed_version=current_version,
        deployed_at=now,
    )


@router.post("/{rule_id}/undeploy", response_model=RuleUndeployResponse)
async def undeploy_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Remove a rule from its percolator index."""
    # Fetch rule with index pattern
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

    if rule.deployed_at is None:
        return RuleUndeployResponse(
            success=True,
            message="Rule was not deployed",
        )

    # Remove from percolator
    percolator = PercolatorService(os_client)
    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
    was_deleted = percolator.undeploy_rule(percolator_index, str(rule.id))

    # Clear deployment tracking and set status to UNDEPLOYED
    rule.deployed_at = None
    rule.deployed_version = None
    rule.status = RuleStatus.UNDEPLOYED
    rule.snooze_until = None
    rule.snooze_indefinite = False

    await db.commit()
    await audit_log(db, current_user.id, "rule.undeploy", "rule", str(rule.id), {"title": rule.title}, ip_address=get_client_ip(request))
    await db.commit()

    return RuleUndeployResponse(
        success=True,
        message="Rule undeployed successfully" if was_deleted else "Rule was not found in percolator index",
    )


@router.post("/{rule_id}/rollback/{version_number}", response_model=RuleRollbackResponse)
async def rollback_rule(
    rule_id: UUID,
    version_number: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """
    Rollback a rule to a previous version.

    Process:
    1. Fetch the specified version
    2. Create a new version with that content
    3. Update rule.yaml_content
    4. Optionally redeploy if rule was deployed
    """
    # Fetch rule with versions
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Find the target version
    target_version = None
    for version in rule.versions:
        if version.version_number == version_number:
            target_version = version
            break

    if target_version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version {version_number} not found",
        )

    # Get current version number
    current_version = rule.versions[0].version_number if rule.versions else 0
    new_version_number = current_version + 1

    # Create new version with old content
    new_version = RuleVersion(
        rule_id=rule_id,
        version_number=new_version_number,
        yaml_content=target_version.yaml_content,
        changed_by=current_user.id,
        change_reason=f"Rollback to version {target_version.version_number}",
        created_at=datetime.now(UTC),
    )
    db.add(new_version)

    # Update rule content
    rule.yaml_content = target_version.yaml_content

    await db.commit()
    await audit_log(db, current_user.id, "rule.rollback", "rule", str(rule.id), {"title": rule.title, "from_version": version_number, "to_version": new_version_number}, ip_address=get_client_ip(request))
    await db.commit()

    return RuleRollbackResponse(
        success=True,
        new_version_number=new_version_number,
        rolled_back_from=version_number,
        yaml_content=target_version.yaml_content,
    )


@router.post("/{rule_id}/snooze")
async def snooze_rule(
    rule_id: UUID,
    snooze_request: SnoozeRequest,
    http_request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Snooze a rule for the specified number of hours or indefinitely."""
    # Validate request
    if not snooze_request.indefinite and snooze_request.hours is None:
        raise HTTPException(status_code=400, detail="Must specify hours or indefinite=true")

    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Cannot snooze undeployed rules
    if rule.status == RuleStatus.UNDEPLOYED:
        raise HTTPException(
            status_code=400,
            detail="Cannot snooze an undeployed rule. Deploy the rule first."
        )

    if snooze_request.indefinite:
        rule.snooze_until = None
        rule.snooze_indefinite = True
        rule.status = RuleStatus.SNOOZED
        snooze_until = None
    else:
        snooze_until = datetime.now(UTC) + timedelta(hours=snooze_request.hours)
        rule.snooze_until = snooze_until
        rule.snooze_indefinite = False
        rule.status = RuleStatus.SNOOZED

    # Update percolator if deployed
    if rule.deployed_at is not None and os_client is not None:
        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
        percolator.update_rule_status(percolator_index, str(rule.id), enabled=False)

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.snooze", "rule", str(rule.id),
        {"title": rule.title, "hours": snooze_request.hours, "indefinite": snooze_request.indefinite},
        ip_address=get_client_ip(http_request)
    )
    await db.commit()

    return {
        "success": True,
        "snooze_until": snooze_until.isoformat() if snooze_until else None,
        "snooze_indefinite": snooze_request.indefinite,
        "status": "snoozed",
    }


@router.post("/{rule_id}/unsnooze")
async def unsnooze_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Remove snooze from a rule."""
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.status = RuleStatus.DEPLOYED
    rule.snooze_until = None
    rule.snooze_indefinite = False

    # Update percolator if deployed
    if rule.deployed_at is not None and os_client is not None:
        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
        percolator.update_rule_status(percolator_index, str(rule.id), enabled=True)

    await db.commit()
    await audit_log(db, current_user.id, "rule.unsnooze", "rule", str(rule.id), {"title": rule.title}, ip_address=get_client_ip(request))
    await db.commit()

    return {"success": True, "status": "enabled"}


# Rule Exception Endpoints


@router.get("/{rule_id}/exceptions", response_model=list[RuleExceptionResponse])
async def list_rule_exceptions(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all exceptions for a rule."""
    # Verify rule exists
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    result = await db.execute(
        select(RuleException)
        .where(RuleException.rule_id == rule_id)
        .order_by(RuleException.created_at.desc())
    )
    return result.scalars().all()


@router.post(
    "/{rule_id}/exceptions",
    response_model=RuleExceptionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule_exception(
    rule_id: UUID,
    exception_data: RuleExceptionCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Create a new exception for a rule."""
    # Verify rule exists
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    exception = RuleException(
        rule_id=rule_id,
        field=exception_data.field,
        operator=exception_data.operator,
        value=exception_data.value,
        reason=exception_data.reason,
        created_by=current_user.id,
    )
    db.add(exception)
    await db.commit()
    await db.refresh(exception)
    await audit_log(db, current_user.id, "exception.create", "rule_exception", str(exception.id), {"rule_id": str(rule_id), "field": exception.field}, ip_address=get_client_ip(request))
    await db.commit()
    return exception


@router.patch(
    "/{rule_id}/exceptions/{exception_id}",
    response_model=RuleExceptionResponse,
)
async def update_rule_exception(
    rule_id: UUID,
    exception_id: UUID,
    exception_data: RuleExceptionUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update an exception (change fields or toggle active state)."""
    result = await db.execute(
        select(RuleException).where(
            RuleException.id == exception_id,
            RuleException.rule_id == rule_id,
        )
    )
    exception = result.scalar_one_or_none()

    if exception is None:
        raise HTTPException(status_code=404, detail="Exception not found")

    update_data = exception_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(exception, field, value)

    await db.commit()
    await db.refresh(exception)
    await audit_log(db, current_user.id, "exception.update", "rule_exception", str(exception.id), {"rule_id": str(rule_id)}, ip_address=get_client_ip(request))
    await db.commit()
    return exception


@router.delete(
    "/{rule_id}/exceptions/{exception_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_rule_exception(
    rule_id: UUID,
    exception_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Delete an exception."""
    result = await db.execute(
        select(RuleException).where(
            RuleException.id == exception_id,
            RuleException.rule_id == rule_id,
        )
    )
    exception = result.scalar_one_or_none()

    if exception is None:
        raise HTTPException(status_code=404, detail="Exception not found")

    # Capture details before delete
    await audit_log(db, current_user.id, "exception.delete", "rule_exception", str(exception_id), {"rule_id": str(rule_id)}, ip_address=get_client_ip(request))
    await db.delete(exception)
    await db.commit()


# Rule Fields Endpoint (for correlation)


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

    # Get fields from OpenSearch index
    try:
        index_pattern = rule.index_pattern.pattern
        # Get all fields from the index
        all_fields = await get_index_fields(os_client, index_pattern)

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

    except Exception as e:
        # If we can't get fields from OpenSearch, return empty list
        # This allows the UI to still function
        return RuleFieldsResponse(fields=[])


# Bulk Operations Endpoints


@router.post("/bulk/enable", response_model=BulkOperationResult)
async def bulk_enable_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Enable multiple rules (also clears any snooze)."""
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
                old_status = rule.status
                rule.status = RuleStatus.DEPLOYED
                rule.snooze_until = None
                rule.snooze_indefinite = False
                success.append(rule_id)

                # Sync status to OpenSearch if deployed
                if rule.deployed_at is not None and os_client is not None and old_status != RuleStatus.DEPLOYED:
                    percolator = PercolatorService(os_client)
                    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
                    percolator.update_rule_status(percolator_index, str(rule.id), enabled=True)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_enable", "rule", None,
        {"count": len(success), "rule_ids": success},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


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

                await db.delete(rule)
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_delete", "rule", None,
        {"count": len(success), "rule_ids": success},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/deploy", response_model=BulkOperationResult)
async def bulk_deploy_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Deploy multiple rules to OpenSearch."""
    success = []
    failed = []

    for rule_id in data.rule_ids:
        try:
            result = await db.execute(
                select(Rule)
                .where(Rule.id == rule_id)
                .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
            )
            rule = result.scalar_one_or_none()
            if rule:
                # First validate the rule
                validation = sigma_service.translate_and_validate(rule.yaml_content)
                if not validation.success:
                    errors_str = ", ".join(e.message for e in (validation.errors or []))
                    failed.append({"id": rule_id, "error": f"Translation failed: {errors_str}"})
                    continue

                # Extract fields and resolve mappings
                sigma_fields = list(validation.fields or set())
                field_mappings_dict: dict[str, str] = {}

                if sigma_fields and rule.index_pattern_id:
                    resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
                    field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

                # Translate rule with field mappings applied
                translation = sigma_service.translate_with_mappings(
                    rule.yaml_content, field_mappings_dict if field_mappings_dict else None
                )
                if not translation.success:
                    errors_str = ", ".join(e.message for e in (translation.errors or []))
                    failed.append({"id": rule_id, "error": f"Translation failed: {errors_str}"})
                    continue

                # Deploy to percolator
                percolator = PercolatorService(os_client)
                percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)

                # Ensure the percolator index exists
                percolator.ensure_percolator_index(percolator_index, rule.index_pattern.pattern)

                # Extract rule metadata from YAML
                parsed_rule = yaml.safe_load(rule.yaml_content)
                tags = parsed_rule.get("tags", [])

                # Deploy the rule - extract inner query for percolator
                percolator_query = translation.query.get("query", translation.query)

                percolator.deploy_rule(
                    percolator_index=percolator_index,
                    rule_id=str(rule.id),
                    query=percolator_query,
                    title=rule.title,
                    severity=rule.severity,
                    tags=tags,
                    enabled=(rule.status == RuleStatus.DEPLOYED),
                )

                # Update rule deployment tracking
                now = datetime.now(UTC)
                current_version = rule.versions[0].version_number if rule.versions else 1
                rule.deployed_at = now
                rule.deployed_version = current_version
                # Set status to DEPLOYED (unless snoozed)
                if rule.status != RuleStatus.SNOOZED:
                    rule.status = RuleStatus.DEPLOYED
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_deploy", "rule", None,
        {"count": len(success), "rule_ids": success},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/undeploy", response_model=BulkOperationResult)
async def bulk_undeploy_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Undeploy multiple rules from OpenSearch."""
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
                if rule.deployed_at is None:
                    # Rule not deployed, but count as success
                    success.append(rule_id)
                    continue

                # Remove from percolator
                percolator = PercolatorService(os_client)
                percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
                percolator.undeploy_rule(percolator_index, str(rule.id))

                # Clear deployment tracking and set status to UNDEPLOYED
                rule.deployed_at = None
                rule.deployed_version = None
                rule.status = RuleStatus.UNDEPLOYED
                rule.snooze_until = None
                rule.snooze_indefinite = False
                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_undeploy", "rule", None,
        {"count": len(success), "rule_ids": success},
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
