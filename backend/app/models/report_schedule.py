"""Scheduled report definitions (F5).

A ReportSchedule captures a recurring detection/compliance report: what to
report on, how often, where to deliver it, and (optionally) which compliance
framework it maps to. A scheduler job (app.services.scheduler) builds and
delivers due reports and advances ``next_run_at``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class ReportType(str, Enum):
    COVERAGE = "coverage"          # ATT&CK coverage posture
    DETECTION_KPIS = "detection_kpis"  # alert volume, FP rate, MTTD
    RULE_HEALTH = "rule_health"    # noisy/stale/deployed rule hygiene
    COMPLIANCE = "compliance"      # framework-mapped control summary


class ReportCadence(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ReportSchedule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "report_schedules"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False, default=ReportType.COVERAGE.value)
    cadence: Mapped[str] = mapped_column(String(16), nullable=False, default=ReportCadence.WEEKLY.value)

    # Optional compliance framework this report is mapped to (pci_dss, soc2,
    # iso_27001, dora). Null for an operational (non-compliance) report.
    framework: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Delivery: a webhook URL (SSRF-validated) and optional auth header. Email
    # delivery reuses the notification settings when target is "email".
    delivery_type: Mapped[str] = mapped_column(String(16), nullable=False, default="webhook")
    delivery_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_header_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    delivery_header_value: Mapped[str | None] = mapped_column(Text, nullable=True)  # encrypted

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
