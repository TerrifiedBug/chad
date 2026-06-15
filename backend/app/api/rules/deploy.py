"""Rule deploy sub-router: bulk deploy/undeploy, per-rule deploy/undeploy, rollback, and rollback-redeploy."""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_active_environment,
    get_opensearch_client,
    require_permission_dep,
)
from app.api.rules._shared import (
    _broadcast_deploy_progress,
    _deployment_pending_response,
    get_settings,
    logger,
    undeploy_linked_correlations,
)
from app.db.session import get_db
from app.models.environment import Environment
from app.models.rule import Rule, RuleStatus, RuleVersion
from app.models.user import User
from app.schemas.bulk import BulkOperationRequest, BulkOperationResult
from app.schemas.rule import (
    RuleDeployResponse,
    RuleRollbackResponse,
    RuleUndeployResponse,
    UnmappedFieldsError,
)
from app.services.attack_sync import update_rule_attack_mappings
from app.services.audit import audit_log
from app.services.deployment import (
    DeploymentApplyError,
    apply_sigma_rule_deployment,
    create_deployment_request,
    is_approval_required,
)
from app.services.environments import (
    get_environment_deployment,
    upsert_environment_deployment,
)
from app.services.field_mapping import resolve_mappings
from app.services.percolator import PercolatorService
from app.services.sigma import sigma_service
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


@router.post("/bulk/deploy", response_model=BulkOperationResult)
async def bulk_deploy_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
):
    """Deploy multiple rules to OpenSearch."""
    # Dual-control gate: file a single batch request for all selected rules.
    if await is_approval_required(db):
        rows = await db.execute(
            select(Rule).where(Rule.id.in_(data.rule_ids)).options(selectinload(Rule.versions))
        )
        rules_found = list(rows.scalars().all())
        if not rules_found:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No matching rules found")
        req = await create_deployment_request(
            db,
            requested_by=current_user.id,
            team_id=current_user.team_id,
            change_reason=data.change_reason,
            sigma_rules=rules_found,
        )
        await audit_log(
            db, current_user.id, "deployment_request.created", "deployment_request",
            str(req.id),
            {"rule_ids": [str(r.id) for r in rules_found], "rule_count": len(rules_found),
             "change_reason": data.change_reason, "via": "bulk_deploy"},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        return _deployment_pending_response(req.id)

    success = []
    failed = []
    # Correlates every deploy_progress event from this one bulk run so the UI can
    # group them into a single progress panel.
    batch_id = str(uuid4())

    for rule_id in data.rule_ids:
        rule = None
        try:
            result = await db.execute(
                select(Rule)
                .where(Rule.id == rule_id)
                .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
            )
            rule = result.scalar_one_or_none()
            if rule:
                # Announce start (best-effort; never blocks the deploy).
                await _broadcast_deploy_progress(
                    batch_id=batch_id, rule_id=str(rule_id), rule_title=rule.title,
                    status="deploying",
                )

                # First validate the rule
                validation = sigma_service.translate_and_validate(rule.yaml_content)
                if not validation.success:
                    errors_str = ", ".join(e.message for e in (validation.errors or []))
                    failed.append({"id": rule_id, "error": f"Translation failed: {errors_str}"})
                    await _broadcast_deploy_progress(
                        batch_id=batch_id, rule_id=str(rule_id), rule_title=rule.title,
                        status="failed", error=f"Translation failed: {errors_str}",
                    )
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
                    await _broadcast_deploy_progress(
                        batch_id=batch_id, rule_id=str(rule_id), rule_title=rule.title,
                        status="failed", error=f"Translation failed: {errors_str}",
                    )
                    continue

                # Extract rule metadata from YAML
                parsed_rule = yaml.safe_load(rule.yaml_content)
                tags = parsed_rule.get("tags", [])

                # Update ATT&CK mappings from rule tags
                # This must happen before deployment so MITRE coverage is accurate
                try:
                    await update_rule_attack_mappings(db, str(rule.id), tags)
                    await db.commit()
                except Exception as e:
                    # Log but don't fail deployment if attack mapping fails
                    logger.warning("Failed to update attack mappings for rule %s: %s", rule.id, e)

                # Deploy to percolator (push mode only)
                # Pull mode doesn't use percolator - rules are evaluated during scheduled polls
                if rule.index_pattern.mode == "push":
                    percolator = PercolatorService(os_client)
                    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)

                    # Ensure the percolator index exists
                    percolator.ensure_percolator_index(percolator_index, rule.index_pattern.pattern)

                    # Deploy the rule - extract inner query for percolator
                    percolator_query = translation.query.get("query", translation.query)

                    percolator.deploy_rule(
                        percolator_index=percolator_index,
                        rule_id=str(rule.id),
                        query=percolator_query,
                        title=rule.title,
                        severity=rule.severity,
                        tags=tags,
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
                await _broadcast_deploy_progress(
                    batch_id=batch_id, rule_id=str(rule_id), rule_title=rule.title,
                    status="success",
                )
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})
            await _broadcast_deploy_progress(
                batch_id=batch_id, rule_id=str(rule_id),
                rule_title=rule.title if rule is not None else str(rule_id),
                status="failed", error=str(e),
            )

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_deploy", "rule", None,
        {"count": len(success), "rule_ids": success, "change_reason": data.change_reason},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed, batch_id=batch_id)


@router.post("/{rule_id}/deploy", response_model=RuleDeployResponse, responses={400: {"model": UnmappedFieldsError}})
async def deploy_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    active_env: Annotated[Environment | None, Depends(get_active_environment)],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
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

    Deploys into the active environment (``X-CHAD-Environment`` header; absent ->
    the default env == today's behavior). The default env keeps the scalar
    Rule.deployed_*/status in sync and uses the legacy percolator namespace.

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

    # Dual-control gate: when global approval is required OR the active env
    # requires deploy approval, file a request instead of writing to the
    # percolator. A second person must approve before apply.
    env_requires_approval = active_env is not None and active_env.require_deploy_approval
    if await is_approval_required(db) or env_requires_approval:
        req = await create_deployment_request(
            db,
            requested_by=current_user.id,
            team_id=rule.team_id,  # scope review to the rule's owning team
            change_reason=change_reason,
            sigma_rules=[rule],
        )
        await audit_log(
            db, current_user.id, "deployment_request.created", "deployment_request",
            str(req.id),
            {"rule_ids": [str(rule.id)], "rule_count": 1, "change_reason": change_reason,
             "via": "deploy"},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        return _deployment_pending_response(req.id)

    # Apply the deployment via the shared service (single source of truth for the
    # validate -> resolve mappings -> translate -> percolator write -> tracking path).
    try:
        result = await apply_sigma_rule_deployment(
            db,
            os_client,
            rule,
            actor_id=current_user.id,
            change_reason=change_reason,
            request_ip=get_client_ip(request),
            environment=active_env,
        )
    except DeploymentApplyError as e:
        if e.kind == "unmapped":
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=UnmappedFieldsError(
                    message=e.message,
                    unmapped_fields=e.unmapped_fields,
                    index_pattern_id=e.index_pattern_id,
                ).model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        ) from e

    return RuleDeployResponse(
        success=True,
        rule_id=result.rule_id,
        percolator_index=result.percolator_index,
        deployed_version=result.deployed_version,
        deployed_at=result.deployed_at,
    )

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
    all_undeployed_correlations = []

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

                # Auto-undeploy any linked correlation rules
                undeployed_correlations = await undeploy_linked_correlations(
                    db, rule_id, current_user.id, data.change_reason, request
                )
                all_undeployed_correlations.extend(undeployed_correlations)

                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_undeploy", "rule", None,
        {
            "count": len(success), "rule_ids": success, "change_reason": data.change_reason,
            "undeployed_correlations": all_undeployed_correlations,
        },
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)




@router.post("/{rule_id}/undeploy", response_model=RuleUndeployResponse)
async def undeploy_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    active_env: Annotated[Environment | None, Depends(get_active_environment)],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
):
    """Remove a rule from the active environment's percolator namespace.

    Undeploys from the active environment (``X-CHAD-Environment``; absent ->
    default env == today's behavior). For the default env the scalar
    Rule.deployed_*/status are cleared (back-compat); the per-env binding is
    marked undeployed for whichever env was targeted.
    """
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

    is_default_env = active_env is None or active_env.is_default

    # Per-env binding state (when not targeting the default env, scalar columns
    # do not describe this env's deployment).
    env_binding = None
    if active_env is not None and not is_default_env:
        env_binding = await get_environment_deployment(db, rule.id, active_env.id)
        if env_binding is None or env_binding.deployed_at is None:
            return RuleUndeployResponse(
                success=True,
                message="Rule was not deployed",
            )
    elif rule.deployed_at is None:
        return RuleUndeployResponse(
            success=True,
            message="Rule was not deployed",
        )

    # Remove from percolator (skip for pull-mode patterns or pull-only deployment)
    settings = get_settings()
    use_percolator = not settings.is_pull_only and rule.index_pattern.mode == "push"

    was_deleted = False
    percolator_index = None
    if use_percolator:
        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(
            rule.index_pattern.pattern, environment=active_env
        )
        was_deleted = percolator.undeploy_rule(percolator_index, str(rule.id))
    else:
        import logging
        logging.getLogger(__name__).info(f"Skipping percolator undeploy for rule {rule.id} (pull mode)")

    # Clear per-env binding (and the scalar columns for the default env).
    if active_env is not None:
        await upsert_environment_deployment(
            db,
            rule_id=rule.id,
            environment_id=active_env.id,
            status=RuleStatus.UNDEPLOYED.value,
            deployed_version=None,
            deployed_at=None,
        )

    if is_default_env:
        # Clear deployment tracking and set status to UNDEPLOYED (back-compat).
        rule.deployed_at = None
        rule.deployed_version = None
        rule.status = RuleStatus.UNDEPLOYED
        rule.snooze_until = None
        rule.snooze_indefinite = False

    # Auto-undeploy any linked correlation rules
    undeployed_correlations = await undeploy_linked_correlations(
        db, rule_id, current_user.id, change_reason, request
    )

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.undeploy", "rule", str(rule.id),
        {"title": rule.title, "change_reason": change_reason, "undeployed_correlations": undeployed_correlations},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    message = "Rule undeployed successfully" if was_deleted else "Rule was not found in percolator index"
    if undeployed_correlations:
        message += (
            f". Also undeployed {len(undeployed_correlations)} correlation rule(s): "
            f"{', '.join(undeployed_correlations)}"
        )

    return RuleUndeployResponse(
        success=True,
        message=message,
    )


@router.post("/{rule_id}/rollback/{version_number}", response_model=RuleRollbackResponse)
async def rollback_rule(
    rule_id: UUID,
    version_number: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
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
        change_reason=change_reason,
        created_at=datetime.now(UTC),
    )
    db.add(new_version)

    # Update rule content
    rule.yaml_content = target_version.yaml_content

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.rollback", "rule", str(rule.id),
        {"title": rule.title, "from_version": version_number, "to_version": new_version_number},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return RuleRollbackResponse(
        success=True,
        new_version_number=new_version_number,
        rolled_back_from=version_number,
        yaml_content=target_version.yaml_content,
    )


@router.post(
    "/{rule_id}/rollback-redeploy/{version_number}",
    response_model=RuleDeployResponse,
    responses={400: {"model": UnmappedFieldsError}},
)
async def rollback_redeploy_rule(
    rule_id: UUID,
    version_number: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
):
    """Roll a rule back to ``version_number`` AND (re)deploy it in one step.

    Reuses the existing rollback logic (a new version carrying the old content
    is created and ``rule.yaml_content`` is updated), then deploys: when the
    dual-control gate is ON a DeploymentRequest is filed (202, like /deploy);
    when OFF the deployment is applied via the shared service. Audited as
    ``rule.rollback`` plus the deploy audit emitted by the shared apply path.
    """
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    # Find the target version to roll back to.
    target_version = next(
        (v for v in rule.versions if v.version_number == version_number), None
    )
    if target_version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version {version_number} not found",
        )

    # --- Rollback (mirrors rollback_rule): create a new version with old content. ---
    current_version = rule.versions[0].version_number if rule.versions else 0
    new_version_number = current_version + 1
    db.add(
        RuleVersion(
            rule_id=rule_id,
            version_number=new_version_number,
            yaml_content=target_version.yaml_content,
            changed_by=current_user.id,
            change_reason=change_reason,
            created_at=datetime.now(UTC),
        )
    )
    rule.yaml_content = target_version.yaml_content
    await db.commit()
    await audit_log(
        db, current_user.id, "rule.rollback", "rule", str(rule.id),
        {"title": rule.title, "from_version": version_number,
         "to_version": new_version_number, "via": "rollback_redeploy"},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    # Reload with the freshly-created version so deploy/pinning sees current content.
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one()

    # --- Deploy. Gate ON -> file a request (202); gate OFF -> apply directly. ---
    if await is_approval_required(db):
        req = await create_deployment_request(
            db,
            requested_by=current_user.id,
            team_id=rule.team_id,
            change_reason=change_reason,
            sigma_rules=[rule],
        )
        await audit_log(
            db, current_user.id, "deployment_request.created", "deployment_request",
            str(req.id),
            {"rule_ids": [str(rule.id)], "rule_count": 1, "change_reason": change_reason,
             "via": "rollback_redeploy"},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        return _deployment_pending_response(req.id)

    try:
        deploy_result = await apply_sigma_rule_deployment(
            db,
            os_client,
            rule,
            actor_id=current_user.id,
            change_reason=change_reason,
            request_ip=get_client_ip(request),
        )
    except DeploymentApplyError as e:
        if e.kind == "unmapped":
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=UnmappedFieldsError(
                    message=e.message,
                    unmapped_fields=e.unmapped_fields,
                    index_pattern_id=e.index_pattern_id,
                ).model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        ) from e

    return RuleDeployResponse(
        success=True,
        rule_id=deploy_result.rule_id,
        percolator_index=deploy_result.percolator_index,
        deployed_version=deploy_result.deployed_version,
        deployed_at=deploy_result.deployed_at,
    )
