"""Health alert suppression tracking for escalation-based rate limiting."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class HealthAlertSuppression(Base, UUIDMixin, TimestampMixin):
    """
    Tracks suppression state for health alerts per (index_pattern, alert_type).

    Suppression levels:
        0 - No suppression (first alert fires immediately)
        1 - 15 minute suppression
        2 - 1 hour suppression
        3 - 4 hour suppression (max level)

    When the condition clears (health returns to normal), suppression is reset.
    """

    __tablename__ = "health_alert_suppressions"
    __table_args__ = (
        UniqueConstraint("index_pattern_id", "alert_type", name="uq_health_suppression"),
    )

    index_pattern_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("index_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # detection_latency, error_rate, no_data, queue_depth
    last_alert_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    suppression_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    index_pattern = relationship("IndexPattern", back_populates="health_suppressions")

    # Suppression intervals in seconds: 0, 15min, 1hr, 4hr
    SUPPRESSION_INTERVALS = [0, 15 * 60, 60 * 60, 4 * 60 * 60]

    def should_suppress(self) -> bool:
        """Check if an alert should be suppressed based on current state."""
        if self.suppression_level == 0 or self.last_alert_at is None:
            return False

        elapsed = (datetime.now(UTC) - self.last_alert_at).total_seconds()
        interval = self.SUPPRESSION_INTERVALS[min(self.suppression_level, 3)]
        return elapsed < interval

    def record_alert(self) -> None:
        """Record that an alert was fired, escalating suppression level."""
        self.last_alert_at = datetime.now(UTC)
        self.suppression_level = min(self.suppression_level + 1, 3)

    def clear(self) -> None:
        """Reset suppression state when condition clears."""
        self.suppression_level = 0
        self.last_alert_at = None
