"""Notification settings models for webhooks and event routing."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Webhook(Base, UUIDMixin, TimestampMixin):
    """Webhook endpoint configuration."""

    __tablename__ = "webhooks"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    header_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    header_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # header_name: Custom header name (e.g., X-API-Key, Authorization)
    # header_value: Encrypted header value (e.g., Bearer token, API key)
    # Provider type for payload formatting: generic, discord, slack
    provider: Mapped[str] = mapped_column(String(20), default="generic")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    system_notifications: Mapped[list[SystemNotificationSetting]] = relationship(
        "SystemNotificationSetting",
        back_populates="webhook",
        cascade="all, delete-orphan",
    )
    alert_notification: Mapped[AlertNotificationSetting | None] = relationship(
        "AlertNotificationSetting",
        back_populates="webhook",
        cascade="all, delete-orphan",
        uselist=False,
    )


class SystemNotificationSetting(Base, UUIDMixin):
    """Maps system event types to webhooks."""

    __tablename__ = "system_notification_settings"
    __table_args__ = (
        UniqueConstraint("event_type", "webhook_id", name="uq_system_notification_event_webhook"),
    )

    # Event types: user_locked, sigmahq_sync_complete, sigmahq_new_rules,
    # attack_sync_complete, sync_failed, health_warning, health_critical,
    # data_freshness_warning, data_freshness_critical
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    webhook: Mapped[Webhook] = relationship("Webhook", back_populates="system_notifications")


class AlertNotificationSetting(Base, UUIDMixin):
    """Per-webhook severity filtering for alert notifications."""

    __tablename__ = "alert_notification_settings"

    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    # Severities to notify on, e.g., ["critical", "high", "medium", "low", "informational"]
    severities: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Whether to include IOC detection alerts (default: off)
    include_ioc_alerts: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    webhook: Mapped[Webhook] = relationship("Webhook", back_populates="alert_notification")


class NotificationSettings(Base, TimestampMixin):
    """Global notification configuration settings (singleton model)."""

    __tablename__ = "notification_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Rule comment governance
    mandatory_rule_comments: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mandatory_comments_deployed_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Health check intervals (in minutes)
    jira_health_interval: Mapped[int] = mapped_column(Integer, default=15)
    sigmahq_health_interval: Mapped[int] = mapped_column(Integer, default=60)
    mitre_health_interval: Mapped[int] = mapped_column(Integer, default=60)
    opensearch_health_interval: Mapped[int] = mapped_column(Integer, default=5)
    ti_health_interval: Mapped[int] = mapped_column(Integer, default=30)

    # Health alert preferences
    health_alert_webhook_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    health_alert_severity: Mapped[str] = mapped_column(String(20), default="warning")
