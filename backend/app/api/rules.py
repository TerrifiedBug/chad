from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_opensearch_client, get_opensearch_client_optional
from app.db.session import get_db
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleStatus, RuleVersion
from app.models.user import User
from app.schemas.rule import (
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
    ValidationErrorItem,
    LogMatchResult,
)
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.sigma import sigma_service

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    status_filter: RuleStatus | None = None,
    skip: int = 0,
    limit: int = 100,
):
    query = select(Rule).offset(skip).limit(limit)
    if status_filter:
        query = query.where(Rule.status == status_filter)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rule = Rule(
        title=rule_data.title,
        description=rule_data.description,
        yaml_content=rule_data.yaml_content,
        severity=rule_data.severity,
        status=rule_data.status,
        index_pattern_id=rule_data.index_pattern_id,
        created_by=current_user.id,
    )
    db.add(rule)
    await db.flush()  # Flush to get the rule.id

    # Create initial version
    version = RuleVersion(
        rule_id=rule.id,
        version_number=1,
        yaml_content=rule_data.yaml_content,
        changed_by=current_user.id,
    )
    db.add(version)

    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=RuleDetailResponse)
async def get_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
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
    return rule


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_data: RuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
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
        )
        db.add(new_version)

    for field, value in update_data.items():
        setattr(rule, field, value)

    await db.commit()
    await db.refresh(rule)

    # If status changed and rule is deployed, sync to OpenSearch
    if "status" in update_data and rule.deployed_at is not None and os_client is not None:
        new_status = update_data["status"]
        if new_status != old_status:
            percolator = PercolatorService(os_client)
            percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
            percolator.update_rule_status(
                percolator_index,
                str(rule.id),
                enabled=(new_status == RuleStatus.ENABLED),
            )

    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

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

        # Check if all rule fields exist in index
        missing_fields = []
        for field in result.fields or set():
            if field not in index_fields:
                missing_fields.append(field)

        if missing_fields:
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
            )

    return RuleValidateResponse(
        valid=True,
        opensearch_query=result.query,
        fields=list(result.fields or set()),
    )


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    request: RuleTestRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Test a Sigma rule against sample log data.

    Does not require OpenSearch - runs in-memory matching.
    """
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

    # Test each log against the rule
    matches = []
    for idx, log in enumerate(request.sample_logs):
        matched = sigma_service.test_against_log(result.query, log)
        matches.append(LogMatchResult(log_index=idx, matched=matched))

    return RuleTestResponse(
        matches=matches,
        opensearch_query=result.query,
    )


@router.post("/{rule_id}/deploy", response_model=RuleDeployResponse)
async def deploy_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
):
    """
    Deploy a rule to its OpenSearch percolator index.

    Process:
    1. Fetch rule and index pattern from DB
    2. Parse Sigma YAML with pySigma
    3. Translate to OpenSearch query
    4. Ensure percolator index exists
    5. Index the percolator document
    6. Update rule.deployed_at timestamp
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

    # Translate rule to OpenSearch query
    translation = sigma_service.translate_and_validate(rule.yaml_content)
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
    import yaml
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
        enabled=(rule.status == RuleStatus.ENABLED),
    )

    # Update rule deployment tracking
    now = datetime.now(timezone.utc)
    current_version = rule.versions[0].version_number if rule.versions else 1
    rule.deployed_at = now
    rule.deployed_version = current_version

    await db.commit()
    await db.refresh(rule)

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
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
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

    # Clear deployment tracking
    rule.deployed_at = None
    rule.deployed_version = None

    await db.commit()

    return RuleUndeployResponse(
        success=True,
        message="Rule undeployed successfully" if was_deleted else "Rule was not found in percolator index",
    )


@router.post("/{rule_id}/rollback/{version_number}", response_model=RuleRollbackResponse)
async def rollback_rule(
    rule_id: UUID,
    version_number: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(get_current_user)],
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
    )
    db.add(new_version)

    # Update rule content
    rule.yaml_content = target_version.yaml_content

    await db.commit()

    # If rule was deployed, redeploy with new content
    if rule.deployed_at is not None:
        translation = sigma_service.translate_and_validate(rule.yaml_content)
        if translation.success:
            percolator = PercolatorService(os_client)
            percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)

            import yaml
            parsed_rule = yaml.safe_load(rule.yaml_content)
            tags = parsed_rule.get("tags", [])

            # Extract inner query for percolator
            percolator_query = translation.query.get("query", translation.query)

            percolator.deploy_rule(
                percolator_index=percolator_index,
                rule_id=str(rule.id),
                query=percolator_query,
                title=rule.title,
                severity=rule.severity,
                tags=tags,
                enabled=(rule.status == RuleStatus.ENABLED),
            )

            rule.deployed_version = new_version_number
            await db.commit()

    return RuleRollbackResponse(
        success=True,
        new_version_number=new_version_number,
        rolled_back_from=version_number,
        yaml_content=target_version.yaml_content,
    )
