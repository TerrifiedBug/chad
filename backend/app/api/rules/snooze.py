"""Rule snooze sub-router: bulk snooze/unsnooze, per-rule snooze/unsnooze, and threshold updates."""
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_active_environment,
    get_opensearch_client_optional,
    require_permission_dep,
)
from app.api.rules._shared import (
    BulkSnoozeRequest,
    SnoozeRequest,
    ThresholdUpdateRequest,
    _deployment_pending_response,
    snooze_linked_correlations,
    unsnooze_linked_correlations,
)
from app.db.session import get_db
from app.models.environment import Environment
from app.models.rule import Rule, RuleStatus
from app.models.user import User
from app.schemas.bulk import BulkOperationRequest, BulkOperationResult
from app.services.audit import audit_log
from app.services.deployment import (
    create_deployment_request,
    is_approval_required,
)
from app.services.environments import (
    get_environment_deployment,
    upsert_environment_deployment,
)
from app.services.percolator import PercolatorService
from app.services.sigma import sigma_service
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


@router.post("/bulk/snooze", response_model=BulkOperationResult)
async def bulk_snooze_rules(
    data: BulkSnoozeRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Snooze multiple rules for the specified number of hours or indefinitely."""
    if not data.indefinite and data.hours is None:
        raise HTTPException(status_code=400, detail="Must specify hours or indefinite=true")

    success = []
    failed = []
    all_snoozed_correlations = []

    # Calculate snooze_until once for all rules
    if data.indefinite:
        snooze_until = None
    else:
        snooze_until = datetime.now(UTC) + timedelta(hours=data.hours)

    for rule_id in data.rule_ids:
        try:
            result = await db.execute(
                select(Rule)
                .where(Rule.id == rule_id)
                .options(selectinload(Rule.index_pattern))
            )
            rule = result.scalar_one_or_none()
            if rule:
                # Cannot snooze undeployed rules
                if rule.status == RuleStatus.UNDEPLOYED:
                    failed.append({"id": rule_id, "error": "Cannot snooze an undeployed rule"})
                    continue

                rule.snooze_until = snooze_until
                rule.snooze_indefinite = data.indefinite
                rule.status = RuleStatus.SNOOZED

                # Remove from percolator when snoozing (prevents alert generation)
                if rule.deployed_at is not None and os_client is not None:
                    percolator = PercolatorService(os_client)
                    percolator_index = percolator.get_percolator_index_name(rule.index_pattern.pattern)
                    percolator.undeploy_rule(percolator_index, str(rule.id))

                # Auto-snooze any linked correlation rules
                snoozed_correlations = await snooze_linked_correlations(
                    db, rule_id, current_user.id, data.change_reason,
                    snooze_until, data.indefinite, request
                )
                all_snoozed_correlations.extend(snoozed_correlations)

                success.append(rule_id)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_snooze", "rule", None,
        {
            "count": len(success),
            "rule_ids": success,
            "hours": data.hours,
            "indefinite": data.indefinite,
            "change_reason": data.change_reason,
            "snoozed_correlations": all_snoozed_correlations,
        },
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


@router.post("/bulk/unsnooze", response_model=BulkOperationResult)
async def bulk_unsnooze_rules(
    data: BulkOperationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Unsnooze multiple rules (clears snooze and sets status to DEPLOYED)."""
    success = []
    failed = []
    all_unsnoozed_correlations = []

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

                # Auto-unsnooze any linked correlation rules
                unsnoozed_correlations = await unsnooze_linked_correlations(
                    db, rule_id, current_user.id, data.change_reason, request
                )
                all_unsnoozed_correlations.extend(unsnoozed_correlations)
            else:
                failed.append({"id": rule_id, "error": "Rule not found"})
        except Exception as e:
            failed.append({"id": rule_id, "error": str(e)})

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.bulk_unsnooze", "rule", None,
        {
            "count": len(success),
            "rule_ids": success,
            "change_reason": data.change_reason,
            "unsnoozed_correlations": all_unsnoozed_correlations,
        },
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return BulkOperationResult(success=success, failed=failed)


@router.post("/{rule_id}/snooze")
async def snooze_rule(
    rule_id: UUID,
    snooze_request: SnoozeRequest,
    http_request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    active_env: Annotated[Environment | None, Depends(get_active_environment)] = None,
):
    """Snooze a rule for the specified number of hours or indefinitely.

    Snoozes in the active environment (``X-CHAD-Environment``; absent -> default
    env == today's behavior). The default env keeps the scalar Rule.snooze_*/
    status in sync; the per-env binding tracks snooze for whichever env.
    """
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

    is_default_env = active_env is None or active_env.is_default

    # Per-env binding (loaded for any concrete env so the upsert below can carry
    # the existing pinned version/deploy time forward). None when active_env is
    # None (pre-migration) or the rule has no binding for that env yet.
    env_binding = None
    if active_env is not None:
        env_binding = await get_environment_deployment(db, rule.id, active_env.id)

    # Cannot snooze undeployed rules. For the default env the scalar status is
    # authoritative; for a non-default env consult that env's binding.
    if is_default_env:
        if rule.status == RuleStatus.UNDEPLOYED:
            raise HTTPException(
                status_code=400,
                detail="Cannot snooze an undeployed rule. Deploy the rule first."
            )
    else:
        if env_binding is None or env_binding.deployed_at is None:
            raise HTTPException(
                status_code=400,
                detail="Cannot snooze an undeployed rule. Deploy the rule first."
            )

    if snooze_request.indefinite:
        snooze_until = None
    else:
        snooze_until = datetime.now(UTC) + timedelta(hours=snooze_request.hours)

    if is_default_env:
        rule.snooze_until = snooze_until
        rule.snooze_indefinite = snooze_request.indefinite
        rule.status = RuleStatus.SNOOZED

    # Update the per-env binding snooze state.
    if active_env is not None:
        await upsert_environment_deployment(
            db,
            rule_id=rule.id,
            environment_id=active_env.id,
            status=RuleStatus.SNOOZED.value,
            deployed_version=(
                rule.deployed_version if is_default_env
                else (env_binding.deployed_version if env_binding else None)
            ),
            deployed_at=(
                rule.deployed_at if is_default_env
                else (env_binding.deployed_at if env_binding else None)
            ),
            snooze_until=snooze_until,
            snooze_indefinite=snooze_request.indefinite,
        )

    # Remove from percolator when snoozing (prevents alert generation)
    deployed = (
        rule.deployed_at is not None if is_default_env
        else (env_binding is not None and env_binding.deployed_at is not None)
    )
    if deployed and os_client is not None:
        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(
            rule.index_pattern.pattern, environment=active_env
        )
        percolator.undeploy_rule(percolator_index, str(rule.id))

    # Auto-snooze any linked correlation rules
    snoozed_correlations = await snooze_linked_correlations(
        db, rule_id, current_user.id, snooze_request.change_reason,
        snooze_until, snooze_request.indefinite, http_request
    )

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.snooze", "rule", str(rule.id),
        {
            "title": rule.title,
            "hours": snooze_request.hours,
            "indefinite": snooze_request.indefinite,
            "change_reason": snooze_request.change_reason,
            "snoozed_correlations": snoozed_correlations,
        },
        ip_address=get_client_ip(http_request)
    )
    await db.commit()

    message = "Rule snoozed"
    if snoozed_correlations:
        message += f". Also snoozed {len(snoozed_correlations)} correlation rule(s): {', '.join(snoozed_correlations)}"

    return {
        "success": True,
        "message": message,
        "snooze_until": snooze_until.isoformat() if snooze_until else None,
        "snooze_indefinite": snooze_request.indefinite,
        "status": "snoozed",
        "snoozed_correlations": snoozed_correlations,
    }


@router.post("/{rule_id}/unsnooze")
async def unsnooze_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("deploy_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    active_env: Annotated[Environment | None, Depends(get_active_environment)] = None,
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
):
    """Remove snooze from a rule in the active environment.

    Unsnoozes in the active environment (``X-CHAD-Environment``; absent ->
    default env == today's behavior), re-writing to that env's percolator
    namespace and clearing the per-env binding snooze.
    """
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    is_default_env = active_env is None or active_env.is_default
    env_requires_approval = active_env is not None and active_env.require_deploy_approval

    # Dual-control gate: unsnoozing re-writes the rule to the percolator, so it
    # is gated too. File a request pinning the current version.
    if await is_approval_required(db) or env_requires_approval:
        rows = await db.execute(
            select(Rule).where(Rule.id == rule_id).options(selectinload(Rule.versions))
        )
        rule_full = rows.scalar_one()
        req = await create_deployment_request(
            db,
            requested_by=current_user.id,
            team_id=rule_full.team_id,  # scope review to the rule's owning team
            change_reason=change_reason,
            sigma_rules=[rule_full],
        )
        await audit_log(
            db, current_user.id, "deployment_request.created", "deployment_request",
            str(req.id),
            {"rule_ids": [str(rule.id)], "rule_count": 1, "change_reason": change_reason,
             "via": "unsnooze"},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        return _deployment_pending_response(req.id)

    # Per-env binding (when not the default env, scalar columns do not describe
    # this env). Determine deployed state for the targeted env.
    env_binding = None
    if active_env is not None and not is_default_env:
        env_binding = await get_environment_deployment(db, rule.id, active_env.id)

    if is_default_env:
        rule.status = RuleStatus.DEPLOYED
        rule.snooze_until = None
        rule.snooze_indefinite = False

    if active_env is not None:
        await upsert_environment_deployment(
            db,
            rule_id=rule.id,
            environment_id=active_env.id,
            status=RuleStatus.DEPLOYED.value,
            deployed_version=(
                rule.deployed_version if is_default_env
                else (env_binding.deployed_version if env_binding else None)
            ),
            deployed_at=(
                rule.deployed_at if is_default_env
                else (env_binding.deployed_at if env_binding else None)
            ),
            snooze_until=None,
            snooze_indefinite=False,
        )

    # Re-deploy to percolator when unsnoozing
    env_deployed = (
        rule.deployed_at is not None if is_default_env
        else (env_binding is not None and env_binding.deployed_at is not None)
    )
    if env_deployed and os_client is not None:
        # Get field mappings for the rule
        from app.services.field_mapping import resolve_mappings

        validation = sigma_service.translate_and_validate(rule.yaml_content)
        sigma_fields = list(validation.fields or set())
        field_mappings_dict: dict[str, str] = {}

        if sigma_fields and rule.index_pattern_id:
            resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
            field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

        # Translate the rule with field mappings
        translation = sigma_service.translate_with_mappings(
            rule.yaml_content, field_mappings_dict if field_mappings_dict else None
        )

        if translation.success:
            # Re-deploy to percolator (push mode only)
            # Pull mode doesn't use percolator - rules are evaluated during scheduled polls
            if rule.index_pattern.mode == "push":
                percolator = PercolatorService(os_client)
                percolator_index = percolator.get_percolator_index_name(
                    rule.index_pattern.pattern, environment=active_env
                )

                # Ensure the percolator index exists
                percolator.ensure_percolator_index(percolator_index, rule.index_pattern.pattern)

                # Extract tags from YAML
                parsed_rule = yaml.safe_load(rule.yaml_content)
                tags = parsed_rule.get("tags", [])

                # Extract the percolator query
                percolator_query = translation.query.get("query", translation.query)

                # Re-deploy to percolator
                percolator.deploy_rule(
                    percolator_index=percolator_index,
                    rule_id=str(rule.id),
                    query=percolator_query,
                    title=rule.title,
                    severity=rule.severity,
                    tags=tags,
                )

    # Auto-unsnooze any linked correlation rules
    unsnoozed_correlations = await unsnooze_linked_correlations(
        db, rule_id, current_user.id, change_reason, request
    )

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.unsnooze", "rule", str(rule.id),
        {
            "title": rule.title,
            "change_reason": change_reason,
            "unsnoozed_correlations": unsnoozed_correlations,
        },
        ip_address=get_client_ip(request)
    )
    await db.commit()

    message = "Rule unsnoozed"
    if unsnoozed_correlations:
        message += f". Also unsnoozed {len(unsnoozed_correlations)} correlation rule(s)"

    return {"success": True, "status": "deployed", "message": message}


@router.patch("/{rule_id}/threshold")
async def update_rule_threshold(
    rule_id: UUID,
    data: ThresholdUpdateRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update threshold settings for a rule with change reason."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Track old values for audit
    old_values = {
        "threshold_enabled": rule.threshold_enabled,
        "threshold_count": rule.threshold_count,
        "threshold_window_minutes": rule.threshold_window_minutes,
        "threshold_group_by": rule.threshold_group_by,
    }

    # Update threshold settings
    rule.threshold_enabled = data.enabled
    rule.threshold_count = data.count if data.enabled else None
    rule.threshold_window_minutes = data.window_minutes if data.enabled else None
    rule.threshold_group_by = data.group_by if data.enabled else None

    new_values = {
        "threshold_enabled": rule.threshold_enabled,
        "threshold_count": rule.threshold_count,
        "threshold_window_minutes": rule.threshold_window_minutes,
        "threshold_group_by": rule.threshold_group_by,
    }

    await db.commit()
    await audit_log(
        db, current_user.id, "rule.threshold_update", "rule", str(rule.id),
        {"title": rule.title, "old_values": old_values, "new_values": new_values, "change_reason": data.change_reason},
        ip_address=get_client_ip(request)
    )
    await db.commit()

    return {
        "success": True,
        "threshold_enabled": rule.threshold_enabled,
        "threshold_count": rule.threshold_count,
        "threshold_window_minutes": rule.threshold_window_minutes,
        "threshold_group_by": rule.threshold_group_by,
    }
