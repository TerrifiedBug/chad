"""
Export API for rules and configuration backup/restore.
"""

import io
import json
import uuid
import zipfile
from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.correlation_rule import CorrelationRule
from app.models.field_mapping import FieldMapping
from app.models.health_alert_suppression import HealthAlertSuppression
from app.models.index_pattern import IndexPattern
from app.models.jira_config import JiraConfig
from app.models.notification_settings import (
    AlertNotificationSetting,
    NotificationSettings,
    SystemNotificationSetting,
    Webhook,
)
from app.models.rule import Rule
from app.models.rule_exception import RuleException
from app.models.setting import Setting
from app.models.ti_config import TISourceConfig
from app.models.user import User

router = APIRouter(prefix="/export", tags=["export"])

# Current config schema version
CONFIG_SCHEMA_VERSION = "3.0"

# Settings to exclude from export (contain credentials)
EXCLUDED_SETTINGS = {"opensearch"}
EXCLUDED_SETTING_PREFIXES = ("secret_",)
EXCLUDED_SETTING_SUFFIXES = ("_token", "_password", "_api_key")


class BulkExportRequest(BaseModel):
    rule_ids: list[str]


def sanitize_filename(title: str) -> str:
    """Sanitize title for use in filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in title)


@router.get("/rules/{rule_id}")
async def export_single_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export a single rule as YAML file."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    safe_title = sanitize_filename(rule.title)
    filename = f"{safe_title}.yml"

    return Response(
        content=rule.yaml_content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/rules/bulk")
async def export_bulk_rules(
    data: BulkExportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export multiple rules as ZIP file."""
    result = await db.execute(select(Rule).where(Rule.id.in_(data.rule_ids)))
    rules = result.scalars().all()

    if not rules:
        raise HTTPException(status_code=404, detail="No rules found for the given IDs")

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = sanitize_filename(rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="chad-rules-{timestamp}.zip"'
        },
    )


@router.get("/rules")
async def export_all_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Export all rules as ZIP file."""
    result = await db.execute(select(Rule))
    rules = result.scalars().all()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            safe_title = sanitize_filename(rule.title)
            zf.writestr(f"{safe_title}.yml", rule.yaml_content)

    zip_buffer.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="chad-rules-all-{timestamp}.zip"'
        },
    )


class ImportMode(str, Enum):
    """Import conflict resolution modes."""

    SKIP = "skip"  # Skip existing items
    OVERWRITE = "overwrite"  # Overwrite existing items
    RENAME = "rename"  # Rename duplicates with suffix


class ImportRequest(BaseModel):
    """Import configuration request."""

    mode: ImportMode = ImportMode.SKIP
    dry_run: bool = False


class ImportSummary(BaseModel):
    """Summary of import operation."""

    dry_run: bool
    created: dict[str, int]
    updated: dict[str, int]
    skipped: dict[str, int]
    errors: list[str]


@router.get("/config")
async def export_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Export comprehensive configuration backup as JSON (no secrets).

    Includes:
    - Index patterns with field mappings
    - Rules with exceptions
    - Correlation rules
    - Webhooks and notification settings (without secrets)
    - TI source configs (without API keys)
    - Users (roles only, no passwords)
    - General settings
    """
    # Get index patterns with field mappings
    patterns_result = await db.execute(
        select(IndexPattern).options(selectinload(IndexPattern.field_mappings))
    )
    index_patterns = []
    for p in patterns_result.scalars():
        pattern_data = {
            "id": str(p.id),
            "name": p.name,
            "pattern": p.pattern,
            "percolator_index": p.percolator_index,
            "description": p.description,
            "allowed_ips": p.allowed_ips,
            "rate_limit_enabled": p.rate_limit_enabled,
            "rate_limit_requests_per_minute": p.rate_limit_requests_per_minute,
            "rate_limit_events_per_minute": p.rate_limit_events_per_minute,
            # Health monitoring thresholds
            "health_alerting_enabled": p.health_alerting_enabled,
            "health_no_data_minutes": p.health_no_data_minutes,
            "health_error_rate_percent": p.health_error_rate_percent,
            "health_detection_latency_warning": p.health_detection_latency_warning,
            "health_detection_latency_critical": p.health_detection_latency_critical,
            "health_opensearch_latency_warning": p.health_opensearch_latency_warning,
            "health_opensearch_latency_critical": p.health_opensearch_latency_critical,
            # Enrichment configuration
            "geoip_fields": p.geoip_fields,
            "ti_config": p.ti_config,
            # Field mappings
            "field_mappings": [
                {
                    "sigma_field": fm.sigma_field,
                    "target_field": fm.target_field,
                    "origin": (
                        fm.origin.value if hasattr(fm.origin, "value") else (fm.origin or "manual")
                    ),
                }
                for fm in p.field_mappings
            ],
        }
        index_patterns.append(pattern_data)

    # Get rules with exceptions
    rules_result = await db.execute(
        select(Rule).options(selectinload(Rule.exceptions))
    )
    rules = []
    for r in rules_result.scalars():
        # Handle source as either enum or string
        source_val = r.source.value if hasattr(r.source, "value") else (r.source or "user")
        # Handle sigmahq_type as either enum or string
        sigmahq_type_val = None
        if r.sigmahq_type:
            sigmahq_type_val = (
                r.sigmahq_type.value if hasattr(r.sigmahq_type, "value") else r.sigmahq_type
            )
        rule_data = {
            "id": str(r.id),
            "title": r.title,
            "description": r.description,
            "yaml_content": r.yaml_content,
            "severity": r.severity,
            "source": source_val,
            "index_pattern_id": str(r.index_pattern_id),
            # Threshold alerting settings
            "threshold_enabled": r.threshold_enabled,
            "threshold_count": r.threshold_count,
            "threshold_window_minutes": r.threshold_window_minutes,
            "threshold_group_by": r.threshold_group_by,
            # Snooze settings
            "snooze_until": r.snooze_until.isoformat() if r.snooze_until else None,
            "snooze_indefinite": r.snooze_indefinite,
            # SigmaHQ metadata
            "sigmahq_path": r.sigmahq_path,
            "sigmahq_type": sigmahq_type_val,
            # Exceptions
            "exceptions": [
                {
                    "field": e.field,
                    "operator": (
                        e.operator.value if hasattr(e.operator, "value") else (e.operator or "equals")
                    ),
                    "value": e.value,
                    "reason": e.reason,
                    "is_active": e.is_active,
                    "group_id": str(e.group_id),
                }
                for e in r.exceptions
            ],
        }
        rules.append(rule_data)

    # Get correlation rules
    corr_result = await db.execute(select(CorrelationRule))
    correlation_rules = [
        {
            "id": str(c.id),
            "name": c.name,
            "rule_a_id": str(c.rule_a_id),
            "rule_b_id": str(c.rule_b_id),
            "entity_field": c.entity_field,
            "entity_field_type": c.entity_field_type,
            "time_window_minutes": c.time_window_minutes,
            "severity": c.severity,
            # Snooze settings
            "snooze_until": c.snooze_until.isoformat() if c.snooze_until else None,
            "snooze_indefinite": c.snooze_indefinite,
        }
        for c in corr_result.scalars()
    ]

    # Get webhooks (without header_value which may contain secrets)
    webhooks_result = await db.execute(
        select(Webhook).options(
            selectinload(Webhook.system_notifications),
            selectinload(Webhook.alert_notification),
        )
    )
    webhooks = []
    for w in webhooks_result.scalars():
        webhook_data = {
            "id": str(w.id),
            "name": w.name,
            "url": w.url,
            "header_name": w.header_name,
            # header_value excluded for security
            "provider": w.provider,
            "enabled": w.enabled,
            "system_notifications": [
                {"event_type": sn.event_type, "enabled": sn.enabled}
                for sn in w.system_notifications
            ],
            "alert_notification": (
                {
                    "severities": w.alert_notification.severities,
                    "enabled": w.alert_notification.enabled,
                }
                if w.alert_notification
                else None
            ),
        }
        webhooks.append(webhook_data)

    # Get notification settings
    notif_result = await db.execute(select(NotificationSettings))
    notif = notif_result.scalar_one_or_none()
    notification_settings = None
    if notif:
        notification_settings = {
            "mandatory_rule_comments": notif.mandatory_rule_comments,
            "mandatory_comments_deployed_only": notif.mandatory_comments_deployed_only,
            "jira_health_interval": notif.jira_health_interval,
            "sigmahq_health_interval": notif.sigmahq_health_interval,
            "mitre_health_interval": notif.mitre_health_interval,
            "opensearch_health_interval": notif.opensearch_health_interval,
            "ti_health_interval": notif.ti_health_interval,
            "health_alert_webhook_enabled": notif.health_alert_webhook_enabled,
            "health_alert_severity": notif.health_alert_severity,
        }

    # Get TI source configs (without API keys)
    ti_result = await db.execute(select(TISourceConfig))
    ti_sources = [
        {
            "source_type": ti.source_type,
            "is_enabled": ti.is_enabled,
            "instance_url": ti.instance_url,
            "config": ti.config,
            # api_key_encrypted excluded for security
        }
        for ti in ti_result.scalars()
    ]

    # Get users (roles only, no passwords/secrets)
    users_result = await db.execute(select(User))
    users = [
        {
            "email": u.email,
            "role": u.role.value if hasattr(u.role, "value") else (u.role or "viewer"),
            "is_active": u.is_active,
            "auth_method": (
                u.auth_method.value if hasattr(u.auth_method, "value") else (u.auth_method or "local")
            ),
            # Excluded: password_hash, totp_secret, totp_backup_codes
        }
        for u in users_result.scalars()
    ]

    # Get Jira config (without API token)
    jira_result = await db.execute(select(JiraConfig))
    jira = jira_result.scalar_one_or_none()
    jira_config = None
    if jira:
        jira_config = {
            "jira_url": jira.jira_url,
            "email": jira.email,
            "default_project": jira.default_project,
            "default_issue_type": jira.default_issue_type,
            "is_enabled": jira.is_enabled,
            "alert_severities": jira.alert_severities,
            # api_token_encrypted excluded for security
        }

    # Get health alert suppression state
    suppression_result = await db.execute(
        select(HealthAlertSuppression).options(selectinload(HealthAlertSuppression.index_pattern))
    )
    health_suppressions = []
    for s in suppression_result.scalars():
        health_suppressions.append({
            "index_pattern_name": s.index_pattern.name if s.index_pattern else None,
            "alert_type": s.alert_type,
            "suppression_level": s.suppression_level,
            "last_alert_at": s.last_alert_at.isoformat() if s.last_alert_at else None,
        })

    # Get settings (filter out sensitive ones using explicit exclusion)
    settings_result = await db.execute(select(Setting))
    settings = {}
    for s in settings_result.scalars():
        # Skip excluded settings
        if s.key in EXCLUDED_SETTINGS:
            continue
        if any(s.key.startswith(prefix) for prefix in EXCLUDED_SETTING_PREFIXES):
            continue
        if any(s.key.endswith(suffix) for suffix in EXCLUDED_SETTING_SUFFIXES):
            continue

        # Special handling for 'ai' setting - strip API key
        if s.key == "ai" and isinstance(s.value, dict):
            ai_config = dict(s.value)
            ai_config.pop("api_key", None)
            settings[s.key] = ai_config
        # Special handling for 'sso' setting - strip client secret
        elif s.key == "sso" and isinstance(s.value, dict):
            sso_config = dict(s.value)
            sso_config.pop("client_secret", None)
            settings[s.key] = sso_config
        else:
            settings[s.key] = s.value

    config = {
        "exported_at": datetime.now().isoformat(),
        "version": CONFIG_SCHEMA_VERSION,
        "index_patterns": index_patterns,
        "rules": rules,
        "correlation_rules": correlation_rules,
        "webhooks": webhooks,
        "notification_settings": notification_settings,
        "ti_sources": ti_sources,
        "jira_config": jira_config,
        "health_suppressions": health_suppressions,
        "users": users,
        "settings": settings,
    }

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return Response(
        content=json.dumps(config, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="chad-config-{timestamp}.json"'
        },
    )


@router.post("/config/import", response_model=ImportSummary)
async def import_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    file: UploadFile = File(...),
    mode: ImportMode = ImportMode.SKIP,
    dry_run: bool = False,
):
    """Import configuration from JSON backup.

    Supports conflict resolution modes:
    - skip: Skip items that already exist
    - overwrite: Update existing items with imported data
    - rename: Create new items with suffix for duplicates

    Use dry_run=true to preview changes without applying them.
    """
    # Read and parse JSON
    try:
        content = await file.read()
        config = json.loads(content.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 encoded")

    # Validate schema version
    version = config.get("version", "1.0")
    if version not in ["1.0", "2.0"]:
        raise HTTPException(400, f"Unsupported config version: {version}")

    summary: dict[str, Any] = {
        "dry_run": dry_run,
        "created": {},
        "updated": {},
        "skipped": {},
        "errors": [],
    }

    # Track ID mappings for v1.0 configs that use names instead of IDs
    index_pattern_id_map: dict[str, str] = {}

    # Import index patterns
    if "index_patterns" in config:
        created, updated, skipped, errors = await _import_index_patterns(
            db, config["index_patterns"], mode, dry_run, current_user,
            index_pattern_id_map
        )
        summary["created"]["index_patterns"] = created
        summary["updated"]["index_patterns"] = updated
        summary["skipped"]["index_patterns"] = skipped
        summary["errors"].extend(errors)

    # Import rules
    if "rules" in config:
        created, updated, skipped, errors = await _import_rules(
            db, config["rules"], mode, dry_run, current_user, index_pattern_id_map
        )
        summary["created"]["rules"] = created
        summary["updated"]["rules"] = updated
        summary["skipped"]["rules"] = skipped
        summary["errors"].extend(errors)

    # Import correlation rules
    if "correlation_rules" in config:
        created, updated, skipped, errors = await _import_correlation_rules(
            db, config["correlation_rules"], mode, dry_run
        )
        summary["created"]["correlation_rules"] = created
        summary["updated"]["correlation_rules"] = updated
        summary["skipped"]["correlation_rules"] = skipped
        summary["errors"].extend(errors)

    # Import webhooks
    if "webhooks" in config:
        created, updated, skipped, errors = await _import_webhooks(
            db, config["webhooks"], mode, dry_run
        )
        summary["created"]["webhooks"] = created
        summary["updated"]["webhooks"] = updated
        summary["skipped"]["webhooks"] = skipped
        summary["errors"].extend(errors)

    # Import notification settings
    if "notification_settings" in config and config["notification_settings"]:
        created, updated, skipped, errors = await _import_notification_settings(
            db, config["notification_settings"], dry_run
        )
        summary["created"]["notification_settings"] = created
        summary["updated"]["notification_settings"] = updated
        summary["skipped"]["notification_settings"] = skipped
        summary["errors"].extend(errors)

    # Import TI sources
    if "ti_sources" in config:
        created, updated, skipped, errors = await _import_ti_sources(
            db, config["ti_sources"], mode, dry_run
        )
        summary["created"]["ti_sources"] = created
        summary["updated"]["ti_sources"] = updated
        summary["skipped"]["ti_sources"] = skipped
        summary["errors"].extend(errors)

    # Import settings
    if "settings" in config:
        created, updated, skipped, errors = await _import_settings(
            db, config["settings"], mode, dry_run
        )
        summary["created"]["settings"] = created
        summary["updated"]["settings"] = updated
        summary["skipped"]["settings"] = skipped
        summary["errors"].extend(errors)

    # Import Jira config (v3.0+)
    if "jira_config" in config and config["jira_config"]:
        created, updated, skipped, errors = await _import_jira_config(
            db, config["jira_config"], mode, dry_run
        )
        summary["created"]["jira_config"] = created
        summary["updated"]["jira_config"] = updated
        summary["skipped"]["jira_config"] = skipped
        summary["errors"].extend(errors)

    # Import health alert suppressions (v3.0+)
    if "health_suppressions" in config and config["health_suppressions"]:
        created, updated, skipped, errors = await _import_health_suppressions(
            db, config["health_suppressions"], dry_run
        )
        summary["created"]["health_suppressions"] = created
        summary["updated"]["health_suppressions"] = updated
        summary["skipped"]["health_suppressions"] = skipped
        summary["errors"].extend(errors)

    # Note: Users are not imported to prevent security issues
    # Admin must create users manually

    if not dry_run:
        await db.commit()

    return ImportSummary(**summary)


async def _import_index_patterns(
    db: AsyncSession,
    patterns: list[dict],
    mode: ImportMode,
    dry_run: bool,
    current_user: User,
    id_map: dict[str, str],
) -> tuple[int, int, int, list[str]]:
    """Import index patterns and field mappings."""
    created = updated = skipped = 0
    errors: list[str] = []

    for p in patterns:
        try:
            # Check if pattern exists by name
            result = await db.execute(
                select(IndexPattern).where(IndexPattern.name == p["name"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    # Store mapping for rules import
                    if "id" in p:
                        id_map[p["id"]] = str(existing.id)
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.pattern = p.get("pattern", existing.pattern)
                        existing.percolator_index = p.get(
                            "percolator_index", existing.percolator_index
                        )
                        existing.description = p.get("description", existing.description)
                        existing.allowed_ips = p.get("allowed_ips")
                        existing.rate_limit_enabled = p.get("rate_limit_enabled", False)
                        existing.rate_limit_requests_per_minute = p.get(
                            "rate_limit_requests_per_minute"
                        )
                        existing.rate_limit_events_per_minute = p.get(
                            "rate_limit_events_per_minute"
                        )
                        # Health monitoring thresholds (v3.0+)
                        if "health_alerting_enabled" in p:
                            existing.health_alerting_enabled = p["health_alerting_enabled"]
                        if "health_no_data_minutes" in p:
                            existing.health_no_data_minutes = p["health_no_data_minutes"]
                        if "health_error_rate_percent" in p:
                            existing.health_error_rate_percent = p["health_error_rate_percent"]
                        if "health_detection_latency_warning" in p:
                            existing.health_detection_latency_warning = p["health_detection_latency_warning"]
                        if "health_detection_latency_critical" in p:
                            existing.health_detection_latency_critical = p["health_detection_latency_critical"]
                        if "health_opensearch_latency_warning" in p:
                            existing.health_opensearch_latency_warning = p["health_opensearch_latency_warning"]
                        if "health_opensearch_latency_critical" in p:
                            existing.health_opensearch_latency_critical = p["health_opensearch_latency_critical"]
                        # Enrichment configuration (v3.0+)
                        if "geoip_fields" in p:
                            existing.geoip_fields = p["geoip_fields"]
                        if "ti_config" in p:
                            existing.ti_config = p["ti_config"]
                    updated += 1
                    if "id" in p:
                        id_map[p["id"]] = str(existing.id)
                    # Import field mappings
                    if "field_mappings" in p and not dry_run:
                        await _import_field_mappings(
                            db, existing.id, p["field_mappings"], current_user
                        )
                else:  # RENAME
                    name = f"{p['name']}_imported_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    if not dry_run:
                        new_pattern = IndexPattern(
                            name=name,
                            pattern=p.get("pattern", ""),
                            percolator_index=p.get("percolator_index"),
                            description=p.get("description"),
                            allowed_ips=p.get("allowed_ips"),
                            rate_limit_enabled=p.get("rate_limit_enabled", False),
                            rate_limit_requests_per_minute=p.get(
                                "rate_limit_requests_per_minute"
                            ),
                            rate_limit_events_per_minute=p.get(
                                "rate_limit_events_per_minute"
                            ),
                            # Health monitoring thresholds (v3.0+)
                            health_alerting_enabled=p.get("health_alerting_enabled", True),
                            health_no_data_minutes=p.get("health_no_data_minutes"),
                            health_error_rate_percent=p.get("health_error_rate_percent"),
                            health_detection_latency_warning=p.get("health_detection_latency_warning"),
                            health_detection_latency_critical=p.get("health_detection_latency_critical"),
                            health_opensearch_latency_warning=p.get("health_opensearch_latency_warning"),
                            health_opensearch_latency_critical=p.get("health_opensearch_latency_critical"),
                            # Enrichment configuration (v3.0+)
                            geoip_fields=p.get("geoip_fields", []),
                            ti_config=p.get("ti_config"),
                        )
                        db.add(new_pattern)
                        await db.flush()
                        if "id" in p:
                            id_map[p["id"]] = str(new_pattern.id)
                        if "field_mappings" in p:
                            await _import_field_mappings(
                                db, new_pattern.id, p["field_mappings"], current_user
                            )
                    created += 1
            else:
                if not dry_run:
                    new_pattern = IndexPattern(
                        name=p["name"],
                        pattern=p.get("pattern", ""),
                        percolator_index=p.get("percolator_index"),
                        description=p.get("description"),
                        allowed_ips=p.get("allowed_ips"),
                        rate_limit_enabled=p.get("rate_limit_enabled", False),
                        rate_limit_requests_per_minute=p.get(
                            "rate_limit_requests_per_minute"
                        ),
                        rate_limit_events_per_minute=p.get(
                            "rate_limit_events_per_minute"
                        ),
                        # Health monitoring thresholds (v3.0+)
                        health_alerting_enabled=p.get("health_alerting_enabled", True),
                        health_no_data_minutes=p.get("health_no_data_minutes"),
                        health_error_rate_percent=p.get("health_error_rate_percent"),
                        health_detection_latency_warning=p.get("health_detection_latency_warning"),
                        health_detection_latency_critical=p.get("health_detection_latency_critical"),
                        health_opensearch_latency_warning=p.get("health_opensearch_latency_warning"),
                        health_opensearch_latency_critical=p.get("health_opensearch_latency_critical"),
                        # Enrichment configuration (v3.0+)
                        geoip_fields=p.get("geoip_fields", []),
                        ti_config=p.get("ti_config"),
                    )
                    db.add(new_pattern)
                    await db.flush()
                    if "id" in p:
                        id_map[p["id"]] = str(new_pattern.id)
                    if "field_mappings" in p:
                        await _import_field_mappings(
                            db, new_pattern.id, p["field_mappings"], current_user
                        )
                created += 1
        except Exception as e:
            errors.append(f"Index pattern '{p.get('name', 'unknown')}': {e}")

    return created, updated, skipped, errors


async def _import_field_mappings(
    db: AsyncSession,
    index_pattern_id: uuid.UUID,
    mappings: list[dict],
    current_user: User,
) -> None:
    """Import field mappings for an index pattern."""
    from app.models.field_mapping import MappingOrigin

    for m in mappings:
        # Check if mapping exists
        result = await db.execute(
            select(FieldMapping).where(
                FieldMapping.index_pattern_id == index_pattern_id,
                FieldMapping.sigma_field == m["sigma_field"],
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.target_field = m["target_field"]
        else:
            origin = MappingOrigin.MANUAL
            if m.get("origin") == "ai_suggested":
                origin = MappingOrigin.AI_SUGGESTED
            new_mapping = FieldMapping(
                index_pattern_id=index_pattern_id,
                sigma_field=m["sigma_field"],
                target_field=m["target_field"],
                origin=origin,
                created_by=current_user.id,
            )
            db.add(new_mapping)


async def _import_rules(
    db: AsyncSession,
    rules: list[dict],
    mode: ImportMode,
    dry_run: bool,
    current_user: User,
    index_pattern_id_map: dict[str, str],
) -> tuple[int, int, int, list[str]]:
    """Import rules with exceptions."""
    from app.models.rule import RuleSource, RuleStatus

    created = updated = skipped = 0
    errors: list[str] = []

    for r in rules:
        try:
            # Map index pattern ID if needed
            ip_id = r.get("index_pattern_id", "")
            if ip_id in index_pattern_id_map:
                ip_id = index_pattern_id_map[ip_id]

            # Validate index pattern exists
            ip_result = await db.execute(
                select(IndexPattern).where(IndexPattern.id == uuid.UUID(ip_id))
            )
            if not ip_result.scalar_one_or_none():
                errors.append(
                    f"Rule '{r.get('title', 'unknown')}': index pattern not found"
                )
                continue

            # Check if rule exists by title
            result = await db.execute(
                select(Rule).where(Rule.title == r["title"])
            )
            rows = result.scalars().all()
            if len(rows) > 1:
                errors.append(
                    f"Rule '{r['title']}': Multiple rules exist with this title, "
                    "cannot determine which to update. Skipping."
                )
                skipped += 1
                continue
            existing = rows[0] if rows else None

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.description = r.get("description")
                        existing.yaml_content = r["yaml_content"]
                        existing.severity = r.get("severity", "medium")
                        existing.index_pattern_id = uuid.UUID(ip_id)
                        # Threshold settings (v3.0+)
                        if "threshold_enabled" in r:
                            existing.threshold_enabled = r["threshold_enabled"]
                        if "threshold_count" in r:
                            existing.threshold_count = r["threshold_count"]
                        if "threshold_window_minutes" in r:
                            existing.threshold_window_minutes = r["threshold_window_minutes"]
                        if "threshold_group_by" in r:
                            existing.threshold_group_by = r["threshold_group_by"]
                        # Snooze settings (v3.0+)
                        if "snooze_indefinite" in r:
                            existing.snooze_indefinite = r["snooze_indefinite"]
                        if "snooze_until" in r and r["snooze_until"]:
                            existing.snooze_until = datetime.fromisoformat(r["snooze_until"])
                        # SigmaHQ metadata (v3.0+)
                        if "sigmahq_path" in r:
                            existing.sigmahq_path = r["sigmahq_path"]
                        if "sigmahq_type" in r:
                            existing.sigmahq_type = r["sigmahq_type"]
                        # Import exceptions
                        if "exceptions" in r:
                            await _import_exceptions(
                                db, existing.id, r["exceptions"], current_user
                            )
                    updated += 1
                else:  # RENAME
                    title = f"{r['title']}_imported"
                    if not dry_run:
                        source = RuleSource.USER
                        if r.get("source") == "sigmahq":
                            source = RuleSource.SIGMAHQ
                        # Parse snooze_until from ISO format
                        snooze_until = None
                        if r.get("snooze_until"):
                            snooze_until = datetime.fromisoformat(r["snooze_until"])
                        new_rule = Rule(
                            title=title,
                            description=r.get("description"),
                            yaml_content=r["yaml_content"],
                            severity=r.get("severity", "medium"),
                            status=RuleStatus.UNDEPLOYED,
                            source=source,
                            index_pattern_id=uuid.UUID(ip_id),
                            created_by=current_user.id,
                            # Threshold settings
                            threshold_enabled=r.get("threshold_enabled", False),
                            threshold_count=r.get("threshold_count"),
                            threshold_window_minutes=r.get("threshold_window_minutes"),
                            threshold_group_by=r.get("threshold_group_by"),
                            # Snooze settings
                            snooze_until=snooze_until,
                            snooze_indefinite=r.get("snooze_indefinite", False),
                            # SigmaHQ metadata
                            sigmahq_path=r.get("sigmahq_path"),
                            sigmahq_type=r.get("sigmahq_type"),
                        )
                        db.add(new_rule)
                        await db.flush()
                        if "exceptions" in r:
                            await _import_exceptions(
                                db, new_rule.id, r["exceptions"], current_user
                            )
                    created += 1
            else:
                if not dry_run:
                    source = RuleSource.USER
                    if r.get("source") == "sigmahq":
                        source = RuleSource.SIGMAHQ
                    # Parse snooze_until from ISO format
                    snooze_until = None
                    if r.get("snooze_until"):
                        snooze_until = datetime.fromisoformat(r["snooze_until"])
                    new_rule = Rule(
                        title=r["title"],
                        description=r.get("description"),
                        yaml_content=r["yaml_content"],
                        severity=r.get("severity", "medium"),
                        status=RuleStatus.UNDEPLOYED,
                        source=source,
                        index_pattern_id=uuid.UUID(ip_id),
                        created_by=current_user.id,
                        # Threshold settings
                        threshold_enabled=r.get("threshold_enabled", False),
                        threshold_count=r.get("threshold_count"),
                        threshold_window_minutes=r.get("threshold_window_minutes"),
                        threshold_group_by=r.get("threshold_group_by"),
                        # Snooze settings
                        snooze_until=snooze_until,
                        snooze_indefinite=r.get("snooze_indefinite", False),
                        # SigmaHQ metadata
                        sigmahq_path=r.get("sigmahq_path"),
                        sigmahq_type=r.get("sigmahq_type"),
                    )
                    db.add(new_rule)
                    await db.flush()
                    if "exceptions" in r:
                        await _import_exceptions(
                            db, new_rule.id, r["exceptions"], current_user
                        )
                created += 1
        except Exception as e:
            errors.append(f"Rule '{r.get('title', 'unknown')}': {e}")

    return created, updated, skipped, errors


async def _import_exceptions(
    db: AsyncSession,
    rule_id: uuid.UUID,
    exceptions: list[dict],
    current_user: User,
) -> None:
    """Import exceptions for a rule."""
    from app.models.rule_exception import ExceptionOperator

    for exc in exceptions:
        operator = ExceptionOperator.EQUALS
        if exc.get("operator"):
            try:
                operator = ExceptionOperator(exc["operator"])
            except ValueError:
                logger.debug("Invalid operator value '%s', using default", exc.get("operator"))

        group_id = uuid.uuid4()
        if exc.get("group_id"):
            try:
                group_id = uuid.UUID(exc["group_id"])
            except ValueError:
                logger.debug("Invalid group_id '%s', generating new UUID", exc.get("group_id"))

        new_exc = RuleException(
            rule_id=rule_id,
            field=exc["field"],
            operator=operator,
            value=exc["value"],
            reason=exc.get("reason"),
            is_active=exc.get("is_active", True),
            group_id=group_id,
            created_by=current_user.id,
        )
        db.add(new_exc)


async def _import_correlation_rules(
    db: AsyncSession,
    corr_rules: list[dict],
    mode: ImportMode,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import correlation rules."""
    created = updated = skipped = 0
    errors: list[str] = []

    for c in corr_rules:
        try:
            # Check if correlation rule exists by name
            result = await db.execute(
                select(CorrelationRule).where(CorrelationRule.name == c["name"])
            )
            rows = result.scalars().all()
            if len(rows) > 1:
                errors.append(
                    f"Correlation rule '{c['name']}': Multiple rules exist with this name, "
                    "cannot determine which to update. Skipping."
                )
                skipped += 1
                continue
            existing = rows[0] if rows else None

            # Validate rule_a and rule_b exist
            rule_a = await db.execute(
                select(Rule).where(Rule.id == uuid.UUID(c["rule_a_id"]))
            )
            rule_b = await db.execute(
                select(Rule).where(Rule.id == uuid.UUID(c["rule_b_id"]))
            )
            if not rule_a.scalar_one_or_none() or not rule_b.scalar_one_or_none():
                errors.append(
                    f"Correlation rule '{c.get('name', 'unknown')}': "
                    "referenced rules not found"
                )
                continue

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.rule_a_id = uuid.UUID(c["rule_a_id"])
                        existing.rule_b_id = uuid.UUID(c["rule_b_id"])
                        existing.entity_field = c["entity_field"]
                        existing.time_window_minutes = c["time_window_minutes"]
                        existing.severity = c["severity"]
                        # New fields (v3.0+)
                        if "entity_field_type" in c:
                            existing.entity_field_type = c["entity_field_type"]
                        if "snooze_indefinite" in c:
                            existing.snooze_indefinite = c["snooze_indefinite"]
                        if "snooze_until" in c and c["snooze_until"]:
                            existing.snooze_until = datetime.fromisoformat(c["snooze_until"])
                    updated += 1
                else:  # RENAME
                    name = f"{c['name']}_imported"
                    if not dry_run:
                        snooze_until = None
                        if c.get("snooze_until"):
                            snooze_until = datetime.fromisoformat(c["snooze_until"])
                        new_corr = CorrelationRule(
                            name=name,
                            rule_a_id=uuid.UUID(c["rule_a_id"]),
                            rule_b_id=uuid.UUID(c["rule_b_id"]),
                            entity_field=c["entity_field"],
                            entity_field_type=c.get("entity_field_type", "sigma"),
                            time_window_minutes=c["time_window_minutes"],
                            severity=c["severity"],
                            snooze_until=snooze_until,
                            snooze_indefinite=c.get("snooze_indefinite", False),
                        )
                        db.add(new_corr)
                    created += 1
            else:
                if not dry_run:
                    snooze_until = None
                    if c.get("snooze_until"):
                        snooze_until = datetime.fromisoformat(c["snooze_until"])
                    new_corr = CorrelationRule(
                        name=c["name"],
                        rule_a_id=uuid.UUID(c["rule_a_id"]),
                        rule_b_id=uuid.UUID(c["rule_b_id"]),
                        entity_field=c["entity_field"],
                        entity_field_type=c.get("entity_field_type", "sigma"),
                        time_window_minutes=c["time_window_minutes"],
                        severity=c["severity"],
                        snooze_until=snooze_until,
                        snooze_indefinite=c.get("snooze_indefinite", False),
                    )
                    db.add(new_corr)
                created += 1
        except Exception as e:
            errors.append(f"Correlation rule '{c.get('name', 'unknown')}': {e}")

    return created, updated, skipped, errors


async def _import_webhooks(
    db: AsyncSession,
    webhooks: list[dict],
    mode: ImportMode,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import webhooks and notification settings."""
    created = updated = skipped = 0
    errors: list[str] = []

    for w in webhooks:
        try:
            # Check if webhook exists by name
            result = await db.execute(
                select(Webhook).where(Webhook.name == w["name"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.url = w["url"]
                        existing.header_name = w.get("header_name")
                        existing.provider = w.get("provider", "generic")
                        existing.enabled = w.get("enabled", True)
                    updated += 1
                else:  # RENAME
                    name = f"{w['name']}_imported"
                    if not dry_run:
                        new_webhook = Webhook(
                            name=name,
                            url=w["url"],
                            header_name=w.get("header_name"),
                            provider=w.get("provider", "generic"),
                            enabled=w.get("enabled", True),
                        )
                        db.add(new_webhook)
                        await db.flush()
                        await _import_webhook_notifications(
                            db, new_webhook.id, w
                        )
                    created += 1
            else:
                if not dry_run:
                    new_webhook = Webhook(
                        name=w["name"],
                        url=w["url"],
                        header_name=w.get("header_name"),
                        provider=w.get("provider", "generic"),
                        enabled=w.get("enabled", True),
                    )
                    db.add(new_webhook)
                    await db.flush()
                    await _import_webhook_notifications(db, new_webhook.id, w)
                created += 1
        except Exception as e:
            errors.append(f"Webhook '{w.get('name', 'unknown')}': {e}")

    return created, updated, skipped, errors


async def _import_webhook_notifications(
    db: AsyncSession,
    webhook_id: uuid.UUID,
    webhook_data: dict,
) -> None:
    """Import system and alert notification settings for a webhook."""
    # Import system notifications
    for sn in webhook_data.get("system_notifications", []):
        new_sn = SystemNotificationSetting(
            webhook_id=webhook_id,
            event_type=sn["event_type"],
            enabled=sn.get("enabled", True),
        )
        db.add(new_sn)

    # Import alert notification
    alert_notif = webhook_data.get("alert_notification")
    if alert_notif:
        new_an = AlertNotificationSetting(
            webhook_id=webhook_id,
            severities=alert_notif.get("severities", []),
            enabled=alert_notif.get("enabled", True),
        )
        db.add(new_an)


async def _import_notification_settings(
    db: AsyncSession,
    settings: dict,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import global notification settings."""
    created = updated = skipped = 0
    errors: list[str] = []

    try:
        result = await db.execute(select(NotificationSettings))
        existing = result.scalar_one_or_none()

        if existing:
            # Check if any values actually differ
            has_changes = False
            for key, value in settings.items():
                if hasattr(existing, key) and getattr(existing, key) != value:
                    has_changes = True
                    break

            if has_changes:
                if not dry_run:
                    for key, value in settings.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                updated = 1
            else:
                skipped = 1
        else:
            if not dry_run:
                new_settings = NotificationSettings(**settings)
                db.add(new_settings)
            created = 1
    except Exception as e:
        errors.append(f"Notification settings: {e}")

    return created, updated, skipped, errors


async def _import_ti_sources(
    db: AsyncSession,
    ti_sources: list[dict],
    mode: ImportMode,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import TI source configs (without API keys)."""
    created = updated = skipped = 0
    errors: list[str] = []

    for ti in ti_sources:
        try:
            result = await db.execute(
                select(TISourceConfig).where(
                    TISourceConfig.source_type == ti["source_type"]
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.is_enabled = ti.get("is_enabled", False)
                        existing.instance_url = ti.get("instance_url")
                        existing.config = ti.get("config")
                        # Note: API key not imported for security
                    updated += 1
                else:  # RENAME - not applicable for TI sources
                    skipped += 1
            else:
                if not dry_run:
                    new_ti = TISourceConfig(
                        source_type=ti["source_type"],
                        is_enabled=ti.get("is_enabled", False),
                        instance_url=ti.get("instance_url"),
                        config=ti.get("config"),
                    )
                    db.add(new_ti)
                created += 1
        except Exception as e:
            errors.append(f"TI source '{ti.get('source_type', 'unknown')}': {e}")

    return created, updated, skipped, errors


async def _import_settings(
    db: AsyncSession,
    settings: dict,
    mode: ImportMode,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import general settings."""
    created = updated = skipped = 0
    errors: list[str] = []

    for key, value in settings.items():
        try:
            result = await db.execute(
                select(Setting).where(Setting.key == key)
            )
            existing = result.scalar_one_or_none()

            if existing:
                if mode == ImportMode.SKIP:
                    skipped += 1
                    continue
                elif mode == ImportMode.OVERWRITE:
                    if not dry_run:
                        existing.value = value
                    updated += 1
                else:  # RENAME - not applicable for settings
                    skipped += 1
            else:
                if not dry_run:
                    new_setting = Setting(key=key, value=value)
                    db.add(new_setting)
                created += 1
        except Exception as e:
            errors.append(f"Setting '{key}': {e}")

    return created, updated, skipped, errors


async def _import_jira_config(
    db: AsyncSession,
    jira_config: dict,
    mode: ImportMode,
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import Jira configuration (without API token)."""
    created = updated = skipped = 0
    errors: list[str] = []

    try:
        result = await db.execute(select(JiraConfig))
        existing = result.scalar_one_or_none()

        if existing:
            if mode == ImportMode.SKIP:
                skipped = 1
            elif mode == ImportMode.OVERWRITE:
                if not dry_run:
                    existing.jira_url = jira_config["jira_url"]
                    existing.email = jira_config["email"]
                    existing.default_project = jira_config["default_project"]
                    existing.default_issue_type = jira_config["default_issue_type"]
                    existing.is_enabled = jira_config.get("is_enabled", True)
                    existing.alert_severities = jira_config.get("alert_severities", [])
                    # Note: api_token_encrypted not imported for security
                updated = 1
            else:  # RENAME - not applicable for singleton
                skipped = 1
        else:
            # Cannot create JiraConfig without API token
            # Mark as skipped with informative error
            errors.append(
                "Jira config: Cannot create new config without API token. "
                "Configure Jira manually after import."
            )
            skipped = 1
    except Exception as e:
        errors.append(f"Jira config: {e}")

    return created, updated, skipped, errors


async def _import_health_suppressions(
    db: AsyncSession,
    suppressions: list[dict],
    dry_run: bool,
) -> tuple[int, int, int, list[str]]:
    """Import health alert suppression state."""
    created = updated = skipped = 0
    errors: list[str] = []

    for s in suppressions:
        try:
            # Find index pattern by name
            if not s.get("index_pattern_name"):
                errors.append("Health suppression: missing index_pattern_name")
                continue

            ip_result = await db.execute(
                select(IndexPattern).where(IndexPattern.name == s["index_pattern_name"])
            )
            index_pattern = ip_result.scalar_one_or_none()
            if not index_pattern:
                errors.append(
                    f"Health suppression for '{s['index_pattern_name']}': "
                    "index pattern not found"
                )
                continue

            # Check if suppression exists
            result = await db.execute(
                select(HealthAlertSuppression).where(
                    HealthAlertSuppression.index_pattern_id == index_pattern.id,
                    HealthAlertSuppression.alert_type == s["alert_type"],
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                if not dry_run:
                    existing.suppression_level = s.get("suppression_level", 0)
                    if s.get("last_alert_at"):
                        existing.last_alert_at = datetime.fromisoformat(s["last_alert_at"])
                updated += 1
            else:
                if not dry_run:
                    last_alert_at = None
                    if s.get("last_alert_at"):
                        last_alert_at = datetime.fromisoformat(s["last_alert_at"])
                    new_suppression = HealthAlertSuppression(
                        index_pattern_id=index_pattern.id,
                        alert_type=s["alert_type"],
                        suppression_level=s.get("suppression_level", 0),
                        last_alert_at=last_alert_at,
                    )
                    db.add(new_suppression)
                created += 1
        except Exception as e:
            errors.append(f"Health suppression: {e}")

    return created, updated, skipped, errors
