"""
Shared deployment service.

Single source of truth for taking a Sigma rule live in the percolator. Both the
direct deploy path (when dual-control is OFF) and the approval-apply path (when
dual-control is ON) call :func:`apply_sigma_rule_deployment`, so the percolator
write, deployment tracking, and audit are identical and correct in one place.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.models.correlation_rule import CorrelationRule, CorrelationRuleVersion
from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestItem,
    DeploymentRequestKind,
    DeploymentRequestStatus,
)
from app.models.environment import Environment
from app.models.notification_settings import NotificationSettings
from app.models.rule import Rule, RuleStatus
from app.services.attack_sync import update_rule_attack_mappings
from app.services.audit import audit_log
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.percolator import PercolatorService
from app.services.sigma import sigma_service

if TYPE_CHECKING:
    from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


class DeploymentApplyError(Exception):
    """Raised when a rule cannot be applied to the percolator.

    ``kind`` distinguishes failure modes so callers can render the right
    response (e.g. the structured 400 ``UnmappedFieldsError`` for ``unmapped``).
    """

    def __init__(
        self,
        message: str,
        *,
        kind: str = "translation",
        unmapped_fields: list[str] | None = None,
        index_pattern_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.unmapped_fields = unmapped_fields or []
        self.index_pattern_id = index_pattern_id


@dataclass
class SigmaDeployResult:
    """Outcome of a successful single-rule percolator apply."""

    rule_id: uuid.UUID
    deployed_version: int
    deployed_at: datetime
    percolator_index: str | None = None
    tags: list[str] = field(default_factory=list)


async def is_approval_required(db: AsyncSession) -> bool:
    """Return whether dual-control deployment approval is currently enabled.

    Reads the ``require_deploy_approval`` flag from the NotificationSettings
    singleton. Missing row (fresh install) means the gate is OFF.
    """
    result = await db.execute(select(NotificationSettings).limit(1))
    settings = result.scalar_one_or_none()
    if settings is None:
        return False
    return bool(settings.require_deploy_approval)


def _current_version(rule: Rule) -> int:
    """Highest version number for a rule (versions ordered desc)."""
    return rule.versions[0].version_number if rule.versions else 1


async def create_deployment_request(
    db: AsyncSession,
    *,
    requested_by: uuid.UUID,
    team_id: uuid.UUID | None,
    change_reason: str,
    sigma_rules: list[Rule] | None = None,
    correlation_rules: list[CorrelationRule] | None = None,
) -> DeploymentRequest:
    """Build a PENDING request, pinning each rule's current version.

    Single source of truth for request creation, used by the generic create
    endpoint and by each gated deploy path (deploy / bulk / unsnooze /
    correlation). Caller owns audit + commit. ``sigma_rules`` must have their
    ``versions`` relationship loaded for correct pinning.
    """
    req = DeploymentRequest(
        requested_by=requested_by,
        team_id=team_id,
        change_reason=change_reason,
        status=DeploymentRequestStatus.PENDING.value,
    )
    for rule in sigma_rules or []:
        req.items.append(
            DeploymentRequestItem(
                rule_id=rule.id,
                rule_version_id=rule.versions[0].id if rule.versions else None,
                version_number=_current_version(rule),
                kind=DeploymentRequestKind.SIGMA.value,
            )
        )
    for corr in correlation_rules or []:
        req.items.append(
            DeploymentRequestItem(
                correlation_rule_id=corr.id,
                version_number=corr.current_version,
                kind=DeploymentRequestKind.CORRELATION.value,
            )
        )
    db.add(req)
    await db.flush()
    return req


async def apply_correlation_rule_deployment(
    db: AsyncSession,
    rule: CorrelationRule,
    *,
    actor_id: uuid.UUID,
    change_reason: str,
    request_ip: str | None = None,
    deployment_request_id: uuid.UUID | None = None,
) -> int:
    """Activate a correlation rule (no percolator; in-app correlation engine).

    Mirrors the direct correlation-deploy endpoint: validate linked rules are
    deployed, snapshot the version, stamp deployment tracking, audit. Returns
    the deployed version number. Raises :class:`DeploymentApplyError` if the
    linked base rules are not deployed.
    """
    linked = (
        await db.execute(select(Rule).where(Rule.id.in_([rule.rule_a_id, rule.rule_b_id])))
    ).scalars().all()
    undeployed = [r for r in linked if r.status != RuleStatus.DEPLOYED]
    if undeployed:
        raise DeploymentApplyError(
            "Cannot deploy correlation rule: linked rules are not deployed: "
            + ", ".join(r.title for r in undeployed),
            kind="ineligible",
        )

    latest = (
        await db.execute(
            select(CorrelationRuleVersion)
            .where(CorrelationRuleVersion.correlation_rule_id == rule.id)
            .order_by(CorrelationRuleVersion.version_number.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if latest is None or latest.version_number != rule.current_version:
        db.add(
            CorrelationRuleVersion(
                correlation_rule_id=rule.id,
                version_number=rule.current_version,
                name=rule.name,
                rule_a_id=rule.rule_a_id,
                rule_b_id=rule.rule_b_id,
                entity_field=rule.entity_field,
                entity_field_type=rule.entity_field_type,
                time_window_minutes=rule.time_window_minutes,
                severity=rule.severity,
                changed_by=actor_id,
                change_reason=change_reason or "Deployed",
            )
        )

    rule.deployed_at = datetime.now(UTC)
    rule.deployed_version = rule.current_version
    await db.commit()
    await db.refresh(rule)

    details: dict = {
        "name": rule.name,
        "deployed_version": rule.deployed_version,
        "change_reason": change_reason,
    }
    if deployment_request_id is not None:
        details["deployment_request_id"] = str(deployment_request_id)
    await audit_log(
        db, actor_id, "correlation_rule_deployed", "correlation_rule", str(rule.id), details,
        ip_address=request_ip,
    )
    await db.commit()
    return rule.deployed_version


async def apply_sigma_rule_deployment(
    db: AsyncSession,
    os_client: OpenSearch,
    rule: Rule,
    *,
    actor_id: uuid.UUID,
    change_reason: str,
    request_ip: str | None = None,
    deployment_request_id: uuid.UUID | None = None,
    pinned_yaml: str | None = None,
    pinned_version: int | None = None,
    environment: Environment | None = None,
) -> SigmaDeployResult:
    """Validate, translate, and write a Sigma rule to its percolator index.

    This is the extracted body of the original ``deploy_rule`` endpoint. The
    ``rule`` must have ``index_pattern`` and ``versions`` eagerly loaded. Raises
    :class:`DeploymentApplyError` for translation / unmapped-field failures so
    the caller can shape the response or mark the request item FAILED.

    When ``deployment_request_id`` is set it is recorded in the audit detail to
    correlate the resulting ``rule.deploy`` row with the approval request.

    Under dual-control, the approval flow passes ``pinned_yaml`` /
    ``pinned_version`` (the exact version that was reviewed) so the content that
    deploys is the content the checker saw — never live content edited after
    review. The direct (gate-off) path leaves these None and deploys live.

    ``environment`` selects the target deployment env (Model B). The write goes
    to that env's percolator namespace and upserts a ``RuleEnvironmentDeployment``
    binding. For the DEFAULT env (or ``environment`` None/legacy) the namespace
    is the legacy ``chad-percolator-{pattern}`` (no re-index) AND the scalar
    ``Rule.deployed_*``/``status`` columns are kept in sync (back-compat).
    """
    # The default env (or None/legacy) is the back-compat path: legacy namespace
    # + scalar Rule.deployed_* sync. Non-default envs only touch the binding.
    is_default_env = environment is None or environment.is_default
    # Deploy the reviewed (pinned) content when provided, else the live rule.
    yaml_content = pinned_yaml if pinned_yaml is not None else rule.yaml_content

    # 1. Validate the rule translates at all.
    validation = sigma_service.translate_and_validate(yaml_content)
    if not validation.success:
        errors_str = ", ".join(e.message for e in (validation.errors or []))
        raise DeploymentApplyError(
            f"Failed to translate rule: {errors_str}", kind="translation"
        )

    # 2. Resolve + auto-correct field mappings; reject unmapped fields.
    sigma_fields = list(validation.fields or set())
    field_mappings_dict: dict[str, str] = {}

    if sigma_fields and rule.index_pattern_id:
        resolved = await resolve_mappings(db, sigma_fields, rule.index_pattern_id)
        field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

        # Auto-correct mappings that point at text fields (keyword sub-field).
        from app.services.field_type_detector import auto_correct_field_mapping

        corrected_mappings: dict[str, str] = {}
        for sigma_field, target_field in field_mappings_dict.items():
            corrected_field, was_corrected = auto_correct_field_mapping(
                os_client, rule.index_pattern.pattern, target_field
            )
            corrected_mappings[sigma_field] = corrected_field
            if was_corrected:
                logger.warning(
                    "Field mapping '%s -> %s' should use '%s' for proper matching. "
                    "Auto-correcting for deployment.",
                    sigma_field,
                    target_field,
                    corrected_field,
                )
        field_mappings_dict = corrected_mappings

        try:
            index_fields = set(
                get_index_fields(os_client, rule.index_pattern.pattern, include_multi_fields=True)
            )
        except Exception:
            index_fields = set()

        unmapped_fields: list[str] = []
        for sigma_field in sigma_fields:
            if sigma_field in field_mappings_dict:
                if field_mappings_dict[sigma_field] in index_fields:
                    continue
            elif sigma_field in index_fields:
                continue
            unmapped_fields.append(sigma_field)

        if unmapped_fields:
            raise DeploymentApplyError(
                "The following fields are not found in the index and have no mappings "
                f"configured: {', '.join(unmapped_fields)}",
                kind="unmapped",
                unmapped_fields=unmapped_fields,
                index_pattern_id=rule.index_pattern_id,
            )

    # 3. Translate with mappings applied.
    translation = sigma_service.translate_with_mappings(
        yaml_content, field_mappings_dict if field_mappings_dict else None
    )
    if not translation.success:
        errors_str = ", ".join(e.message for e in (translation.errors or []))
        raise DeploymentApplyError(
            f"Failed to translate rule: {errors_str}", kind="translation"
        )

    # 4. Update ATT&CK mappings from tags before deploy so MITRE coverage is accurate.
    parsed_rule = yaml.safe_load(yaml_content)
    tags = parsed_rule.get("tags", []) if isinstance(parsed_rule, dict) else []
    try:
        await update_rule_attack_mappings(db, str(rule.id), tags)
        await db.commit()
    except Exception as e:
        logger.warning("Failed to update attack mappings for rule %s: %s", rule.id, e)

    # 5. Deploy to percolator (push mode only; pull mode evaluates during polls).
    use_percolator = not app_settings.is_pull_only and rule.index_pattern.mode == "push"
    percolator_index: str | None = None
    if use_percolator:
        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(
            rule.index_pattern.pattern, environment=environment
        )
        percolator.ensure_percolator_index(percolator_index, rule.index_pattern.pattern)
        # Sigma returns {"query": {...}}, percolator needs the inner query.
        percolator_query = translation.query.get("query", translation.query)
        percolator.deploy_rule(
            percolator_index=percolator_index,
            rule_id=str(rule.id),
            query=percolator_query,
            title=rule.title,
            severity=rule.severity,
            tags=tags,
        )
    else:
        logger.info("Skipping percolator deploy for rule %s (pull mode)", rule.id)

    # 6. Update deployment tracking. The deployed version reflects what was
    # actually pushed (the pinned/reviewed version under dual-control).
    now = datetime.now(UTC)
    deploy_version = pinned_version if pinned_version is not None else _current_version(rule)

    # 6a. The default env (or legacy None) keeps the scalar Rule.deployed_*/
    # status columns in sync so existing reads/UX/live detection are unchanged.
    if is_default_env:
        rule.deployed_at = now
        rule.deployed_version = deploy_version
        if rule.status != RuleStatus.SNOOZED:
            rule.status = RuleStatus.DEPLOYED

    # 6b. Upsert the per-env deployment binding (Model B). Snoozed rules keep
    # their per-env snooze status; otherwise the binding is marked deployed.
    if environment is not None:
        from app.services.environments import upsert_environment_deployment

        binding_status = (
            RuleStatus.SNOOZED.value
            if rule.status == RuleStatus.SNOOZED and is_default_env
            else RuleStatus.DEPLOYED.value
        )
        await upsert_environment_deployment(
            db,
            rule_id=rule.id,
            environment_id=environment.id,
            status=binding_status,
            deployed_version=deploy_version,
            deployed_at=now,
        )

    await db.commit()
    await db.refresh(rule)

    # 7. Audit, correlating to the approval request when applicable.
    details: dict = {
        "title": rule.title,
        "percolator_index": percolator_index,
        "change_reason": change_reason,
    }
    if environment is not None:
        details["environment_id"] = str(environment.id)
        details["environment"] = environment.name
    if deployment_request_id is not None:
        details["deployment_request_id"] = str(deployment_request_id)
    await audit_log(db, actor_id, "rule.deploy", "rule", str(rule.id), details, ip_address=request_ip)
    await db.commit()

    return SigmaDeployResult(
        rule_id=rule.id,
        deployed_version=deploy_version,
        deployed_at=now,
        percolator_index=percolator_index,
        tags=tags,
    )
