from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.rule import Rule
    from app.models.user import User


class Alert(Base, UUIDMixin, TimestampMixin):
    """Database model tracking alerts stored in OpenSearch.

    This table keeps metadata about alerts for audit and management purposes.
    The actual alert data (log document, matched fields) is stored in OpenSearch.
    """

    __tablename__ = "alerts"

    # OpenSearch reference
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    """OpenSearch document ID"""

    alert_index: Mapped[str] = mapped_column(String(255), nullable=False)
    """OpenSearch index name where alert is stored"""

    # Alert details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    """Alert title (typically rule title)"""

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False
    )
    """Rule that generated this alert"""

    # Alert status
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="new"
    )
    """Status: new, acknowledged, resolved, false_positive"""

    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    """Alert severity level"""

    # Acknowledgement tracking
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    """User who acknowledged the alert"""

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    """When the alert was acknowledged"""
