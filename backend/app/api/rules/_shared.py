"""Shared imports, schemas, and helpers for the rules router package.

Extracted verbatim from the original ``app/api/rules.py`` so the
sub-routers (crud, testing, deploy, snooze, exceptions, metadata) can
share them. No ``router`` is defined here; each sub-module owns its own.
"""
import logging
from datetime import UTC, datetime
from uuid import UUID

from fastapi import Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.models.correlation_rule import CorrelationRule
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.schemas.rule import (
    FieldMappingInfo,
)
from app.services.audit import audit_log
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.sigma import sigma_service
from app.utils.request import get_client_ip


def get_settings():
    """Get application settings (for easier mocking in tests)."""
    return app_settings


def _deployment_pending_response(request_id, message: str | None = None):
    """202 body returned when dual-control gating defers a deploy to approval."""
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "pending_approval",
            "deployment_request_id": str(request_id),
            "message": message
            or "Deployment requires approval; a request has been submitted for review.",
        },
    )

logger = logging.getLogger(__name__)

async def _broadcast_deploy_progress(
    *,
    batch_id: str,
    rule_id: str,
    rule_title: str,
    status: str,
    error: str | None = None,
) -> None:
    """Best-effort push of a deploy_progress event over the existing /ws.

    Reuses the WebSocket manager's ``broadcast_to_all_local`` (the same helper
    that fans out system_log / alert messages). Never raises: a broadcast
    failure must not affect the deployment hot path.
    """
    try:
        from app.services.websocket import manager

        await manager.broadcast_to_all_local(
            {
                "type": "deploy_progress",
                "batch_id": batch_id,
                "rule_id": rule_id,
                "rule_title": rule_title,
                "status": status,
                "error": error,
            }
        )
    except Exception as exc:  # noqa: BLE001 - progress UI is non-critical
        logger.debug("deploy_progress broadcast failed: %s", exc)


class SnoozeRequest(BaseModel):
    hours: int | None = Field(default=None, ge=1, le=168)  # None allowed if indefinite
    indefinite: bool = False
    change_reason: str = Field(..., min_length=1, max_length=10000)


class BulkSnoozeRequest(BaseModel):
    """Request body for bulk snooze operations."""
    rule_ids: list[str]
    hours: int | None = Field(default=None, ge=1, le=168)  # None allowed if indefinite
    indefinite: bool = False
    change_reason: str = Field(..., min_length=1, max_length=10000)


class ThresholdUpdateRequest(BaseModel):
    """Request body for updating threshold settings."""
    enabled: bool
    count: int | None = Field(default=None, ge=1)
    window_minutes: int | None = Field(default=None, ge=1)
    group_by: str | None = None
    change_reason: str = Field(..., min_length=1, max_length=10000)


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


async def _evaluate_rule_eligibility(
    db: AsyncSession,
    rule: Rule,
    index_pattern: IndexPattern | None,
    os_client: OpenSearch | None,
) -> tuple[bool, str | None, list[str]]:
    """Single-rule deployment eligibility (shared by check-deployment-eligibility
    and deploy-preview).

    Returns ``(eligible, reason, unmapped_fields)``. Mirrors the per-rule body of
    :func:`check_deployment_eligibility`: translate the YAML, resolve mappings,
    and flag fields that neither exist in the index nor map to one that does.
    """
    if index_pattern is None:
        return False, "Index pattern not found", []

    try:
        result = sigma_service.translate_and_validate(rule.yaml_content)
        if not result.success:
            errors_str = ", ".join(e.message for e in (result.errors or []))
            return False, f"Invalid rule: {errors_str}", []

        detected_fields = list(result.fields or set())
        if not detected_fields:
            return True, None, []

        try:
            if os_client:
                index_fields = set(
                    get_index_fields(os_client, index_pattern.pattern, include_multi_fields=True)
                )
            else:
                index_fields = set()
        except Exception:
            index_fields = set()

        mappings = await resolve_mappings(db, detected_fields, rule.index_pattern_id)

        unmapped: list[str] = []
        for field in detected_fields:
            if field in mappings and mappings[field] is not None:
                if mappings[field] in index_fields:
                    continue
            elif field in index_fields:
                continue
            unmapped.append(field)

        if unmapped:
            return False, f"Unmapped fields: {', '.join(unmapped)}", unmapped
        return True, None, []
    except Exception as e:  # noqa: BLE001 - surface any unexpected error as ineligible
        return False, str(e), []


async def undeploy_linked_correlations(
    db: AsyncSession,
    rule_id: UUID,
    user_id: UUID,
    change_reason: str,
    request: Request,
) -> list[str]:
    """
    Undeploy any deployed correlation rules that depend on this rule.

    Returns list of undeployed correlation rule names.
    """

    # Find deployed correlation rules that reference this rule
    result = await db.execute(
        select(CorrelationRule).where(
            or_(
                CorrelationRule.rule_a_id == rule_id,
                CorrelationRule.rule_b_id == rule_id,
            ),
            CorrelationRule.deployed_at.isnot(None),
        )
    )
    correlations = result.scalars().all()

    undeployed_names = []
    for corr in correlations:
        old_deployed_version = corr.deployed_version
        corr.deployed_at = None
        corr.deployed_version = None
        undeployed_names.append(corr.name)

        # Log audit event for each correlation
        await audit_log(
            db,
            user_id,
            "correlation_rule_undeployed",
            "correlation_rule",
            str(corr.id),
            {
                "name": corr.name,
                "previous_deployed_version": old_deployed_version,
                "change_reason": f"Auto-undeployed: underlying rule undeployed. {change_reason}",
                "triggered_by_rule_id": str(rule_id),
            },
            ip_address=get_client_ip(request),
        )

    return undeployed_names


async def snooze_linked_correlations(
    db: AsyncSession,
    rule_id: UUID,
    user_id: UUID,
    change_reason: str,
    snooze_until: datetime | None,
    snooze_indefinite: bool,
    request: Request,
) -> list[str]:
    """
    Snooze any deployed correlation rules that depend on this rule.

    Returns list of snoozed correlation rule names.
    """

    # Find deployed correlation rules that reference this rule (and not already snoozed)
    result = await db.execute(
        select(CorrelationRule).where(
            or_(
                CorrelationRule.rule_a_id == rule_id,
                CorrelationRule.rule_b_id == rule_id,
            ),
            CorrelationRule.deployed_at.isnot(None),
            CorrelationRule.snooze_indefinite == False,  # noqa: E712
            or_(
                CorrelationRule.snooze_until.is_(None),
                CorrelationRule.snooze_until < datetime.now(UTC),
            ),
        )
    )
    correlations = result.scalars().all()

    snoozed_names = []
    for corr in correlations:
        corr.snooze_until = snooze_until
        corr.snooze_indefinite = snooze_indefinite
        snoozed_names.append(corr.name)

        # Log audit event for each correlation
        await audit_log(
            db,
            user_id,
            "correlation_rule.snooze",
            "correlation_rule",
            str(corr.id),
            {
                "name": corr.name,
                "snooze_until": snooze_until.isoformat() if snooze_until else None,
                "snooze_indefinite": snooze_indefinite,
                "change_reason": f"Auto-snoozed: underlying rule snoozed. {change_reason}",
                "triggered_by_rule_id": str(rule_id),
            },
            ip_address=get_client_ip(request),
        )

    return snoozed_names


async def unsnooze_linked_correlations(
    db: AsyncSession,
    rule_id: UUID,
    user_id: UUID,
    change_reason: str,
    request: Request,
) -> list[str]:
    """
    Unsnooze any snoozed correlation rules that depend on this rule.

    Returns list of unsnoozed correlation rule names.
    """

    # Find snoozed correlation rules that reference this rule
    result = await db.execute(
        select(CorrelationRule).where(
            or_(
                CorrelationRule.rule_a_id == rule_id,
                CorrelationRule.rule_b_id == rule_id,
            ),
            CorrelationRule.deployed_at.isnot(None),
            or_(
                CorrelationRule.snooze_indefinite == True,  # noqa: E712
                CorrelationRule.snooze_until > datetime.now(UTC),
            ),
        )
    )
    correlations = result.scalars().all()

    unsnoozed_names = []
    for corr in correlations:
        corr.snooze_until = None
        corr.snooze_indefinite = False
        unsnoozed_names.append(corr.name)

        # Log audit event for each correlation
        await audit_log(
            db,
            user_id,
            "correlation_rule.unsnooze",
            "correlation_rule",
            str(corr.id),
            {
                "name": corr.name,
                "change_reason": f"Auto-unsnoozed: underlying rule unsnoozed. {change_reason}",
                "triggered_by_rule_id": str(rule_id),
            },
            ip_address=get_client_ip(request),
        )

    return unsnoozed_names
