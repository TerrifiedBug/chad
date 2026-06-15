"""Rule testing sub-router: validate, deployment-eligibility, deploy-preview, test, and historical test."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from opensearchpy import OpenSearch
from sqlalchemy import select
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
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.models.user import User
from app.schemas.rule import (
    DeployPreviewEligibility,
    DeployPreviewResponse,
    DeployPreviewValidation,
    HistoricalTestRequest,
    HistoricalTestResponse,
    LogMatchResult,
    RuleTestRequest,
    RuleTestResponse,
    RuleValidateRequest,
    RuleValidateResponse,
    ValidationErrorItem,
)
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.rule_testing import run_historical_test
from app.services.sigma import sigma_service

router = APIRouter(prefix="/rules", tags=["rules"])


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
                        f"Auto-corrected field mapping in validation: '{sigma_field}' -> "
                        f"'{target_field}' to '{corrected_field}'"
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

