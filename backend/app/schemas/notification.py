"""Notification settings schemas for API request/response validation."""

from uuid import UUID

from pydantic import BaseModel


class SystemNotificationConfig(BaseModel):
    """Configuration for a single system event type."""

    event_type: str
    webhook_ids: list[UUID]  # Which webhooks receive this event


class AlertNotificationConfig(BaseModel):
    """Configuration for alert notifications per webhook."""

    webhook_id: UUID
    webhook_name: str
    severities: list[str]  # Which severities this webhook receives
    enabled: bool


class NotificationSettingsResponse(BaseModel):
    """Full notification settings response."""

    system_events: list[SystemNotificationConfig]
    alert_notifications: list[AlertNotificationConfig]


class UpdateSystemNotificationRequest(BaseModel):
    """Update which webhooks receive a system event."""

    event_type: str
    webhook_ids: list[UUID]


class UpdateAlertNotificationRequest(BaseModel):
    """Update alert notification settings for a webhook."""

    webhook_id: UUID
    severities: list[str]
    enabled: bool


class MandatoryCommentsConfig(BaseModel):
    """Configuration for mandatory rule change comments."""

    mandatory_rule_comments: bool
    mandatory_comments_deployed_only: bool
