"""
Notifications settings API endpoints.

Manage notification routing for system events and alerts. Admin access required.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from opensearchpy import OpenSearch
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_opensearch_client, require_admin
from app.db.session import get_db
from app.models.notification_settings import (
    AlertNotificationSetting,
    NotificationSettings,
    SystemNotificationSetting,
    Webhook,
)
from app.models.user import User
from app.schemas.notification import (
    AlertNotificationConfig,
    MandatoryCommentsConfig,
    NotificationSettingsResponse,
    SystemNotificationConfig,
    UpdateAlertNotificationRequest,
    UpdateSystemNotificationRequest,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/notifications", tags=["notifications"])

SYSTEM_EVENT_TYPES = [
    # Security
    "user_locked",
    # Sync events
    "sigmahq_sync_complete",
    "sigmahq_new_rules",
    "attack_sync_complete",
    "sync_failed",
    "sigmahq_sync_failed",
    "attack_sync_failed",
    # Health & Infrastructure
    "health_warning",
    "health_critical",
    "opensearch_connection_lost",
    "opensearch_connection_restored",
    # Rule operations
    "rule_deployment_failed",
    "percolator_query_error",
    # Integration failures
    "maxmind_update_failed",
    "ai_mapping_failed",
    "webhook_delivery_failed",
]


@router.get("", response_model=NotificationSettingsResponse)
async def get_notification_settings(
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get all notification settings."""
    # Get system notification settings grouped by event type
    result = await db.execute(
        select(SystemNotificationSetting).options(selectinload(SystemNotificationSetting.webhook))
    )
    system_settings = result.scalars().all()

    # Group by event type
    event_webhooks: dict[str, list[UUID]] = {et: [] for et in SYSTEM_EVENT_TYPES}
    for setting in system_settings:
        if setting.enabled and setting.event_type in event_webhooks:
            event_webhooks[setting.event_type].append(setting.webhook_id)

    system_events = [SystemNotificationConfig(event_type=et, webhook_ids=wids) for et, wids in event_webhooks.items()]

    # Get alert notification settings
    result = await db.execute(select(AlertNotificationSetting).options(selectinload(AlertNotificationSetting.webhook)))
    alert_settings = result.scalars().all()

    # Get all webhooks to show unconfigured ones too
    result = await db.execute(select(Webhook))
    all_webhooks = result.scalars().all()
    webhook_map = {w.id: w for w in all_webhooks}

    alert_notifications = []
    configured_webhook_ids = {s.webhook_id for s in alert_settings}

    for setting in alert_settings:
        webhook = webhook_map.get(setting.webhook_id)
        if webhook:
            alert_notifications.append(
                AlertNotificationConfig(
                    webhook_id=setting.webhook_id,
                    webhook_name=webhook.name,
                    severities=setting.severities,
                    enabled=setting.enabled,
                )
            )

    # Add unconfigured webhooks with empty severities
    for webhook in all_webhooks:
        if webhook.id not in configured_webhook_ids:
            alert_notifications.append(
                AlertNotificationConfig(
                    webhook_id=webhook.id,
                    webhook_name=webhook.name,
                    severities=[],
                    enabled=False,
                )
            )

    return NotificationSettingsResponse(
        system_events=system_events,
        alert_notifications=alert_notifications,
    )


@router.put("/system")
async def update_system_notification(
    data: UpdateSystemNotificationRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update which webhooks receive a system event type."""
    if data.event_type not in SYSTEM_EVENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {data.event_type}")

    # Verify all webhook IDs exist
    if data.webhook_ids:
        result = await db.execute(select(Webhook.id).where(Webhook.id.in_(data.webhook_ids)))
        existing_ids = set(result.scalars().all())
        invalid_ids = set(data.webhook_ids) - existing_ids
        if invalid_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid webhook IDs: {[str(id) for id in invalid_ids]}",
            )

    # Delete existing settings for this event type
    await db.execute(delete(SystemNotificationSetting).where(SystemNotificationSetting.event_type == data.event_type))

    # Create new settings
    for webhook_id in data.webhook_ids:
        setting = SystemNotificationSetting(
            event_type=data.event_type,
            webhook_id=webhook_id,
            enabled=True,
        )
        db.add(setting)

    await audit_log(
        db,
        current_user.id,
        "notification.system.update",
        "notification_setting",
        data.event_type,
        {"event_type": data.event_type, "webhook_ids": [str(id) for id in data.webhook_ids]},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"success": True}


@router.put("/alerts")
async def update_alert_notification(
    data: UpdateAlertNotificationRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update alert notification settings for a webhook."""
    # Check webhook exists
    webhook = await db.get(Webhook, data.webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Upsert alert notification setting
    result = await db.execute(
        select(AlertNotificationSetting).where(AlertNotificationSetting.webhook_id == data.webhook_id)
    )
    setting = result.scalar_one_or_none()

    if setting:
        setting.severities = data.severities
        setting.enabled = data.enabled
    else:
        setting = AlertNotificationSetting(
            webhook_id=data.webhook_id,
            severities=data.severities,
            enabled=data.enabled,
        )
        db.add(setting)

    await audit_log(
        db,
        current_user.id,
        "notification.alert.update",
        "notification_setting",
        str(data.webhook_id),
        {
            "webhook_id": str(data.webhook_id),
            "webhook_name": webhook.name,
            "severities": data.severities,
            "enabled": data.enabled,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"success": True}


@router.get("/settings", response_model=MandatoryCommentsConfig)
async def get_mandatory_comments_settings(
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get mandatory comments configuration settings."""
    result = await db.execute(select(NotificationSettings).limit(1))
    settings = result.scalar_one_or_none()

    if not settings:
        # Return defaults if no settings exist
        return MandatoryCommentsConfig(
            mandatory_rule_comments=True,
            mandatory_comments_deployed_only=False,
        )

    return MandatoryCommentsConfig(
        mandatory_rule_comments=settings.mandatory_rule_comments,
        mandatory_comments_deployed_only=settings.mandatory_comments_deployed_only,
    )


@router.get("/settings/public")
async def get_mandatory_comments_settings_public(
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get mandatory comments configuration (public endpoint for all users)."""
    result = await db.execute(select(NotificationSettings).limit(1))
    settings = result.scalar_one_or_none()

    if not settings:
        # Return defaults if no settings exist
        return {"mandatory_rule_comments": True}

    return {"mandatory_rule_comments": settings.mandatory_rule_comments}


@router.put("/settings")
async def update_mandatory_comments_settings(
    data: MandatoryCommentsConfig,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update mandatory comments configuration settings."""
    result = await db.execute(select(NotificationSettings).limit(1))
    settings = result.scalar_one_or_none()

    if settings:
        settings.mandatory_rule_comments = data.mandatory_rule_comments
        settings.mandatory_comments_deployed_only = data.mandatory_comments_deployed_only
    else:
        settings = NotificationSettings(
            mandatory_rule_comments=data.mandatory_rule_comments,
            mandatory_comments_deployed_only=data.mandatory_comments_deployed_only,
        )
        db.add(settings)

    await audit_log(
        db,
        current_user.id,
        "notification.settings.update",
        "notification_setting",
        "mandatory_comments",
        {
            "mandatory_rule_comments": data.mandatory_rule_comments,
            "mandatory_comments_deployed_only": data.mandatory_comments_deployed_only,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"message": "Settings updated successfully"}


@router.get("/recent")
async def get_recent_notifications(
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Get recent notifications for the current user.

    Returns current health issues.
    Note: Security alerts are stored in OpenSearch and not included here.
    """
    from app.services.health import get_all_indices_health

    # Get health status for all indices
    index_health = await get_all_indices_health(db, os_client)

    # Filter to only show warning/critical health issues
    health_issues = [
        {
            "index_pattern_id": h["index_pattern_id"],
            "index_pattern_name": h["index_pattern_name"],
            "status": h["status"],
            "issues": h["issues"],
        }
        for h in index_health
        if h["status"] in ["warning", "critical"]
    ]

    return {
        "security_alerts": [],
        "health_issues": health_issues,
    }

