"""Track threshold state for rules with count-based alerting."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class ThresholdMatch(Base, UUIDMixin):
    """Track individual matches for threshold counting.

    When a rule with threshold alerting matches a log, we record it here.
    Once the count exceeds the threshold within the time window, we create
    an alert and clear the matches for that group.
    """
    __tablename__ = "threshold_matches"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False
    )
    group_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    log_id: Mapped[str] = mapped_column(String(100), nullable=False)
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index('ix_threshold_matches_rule_group_time', 'rule_id', 'group_value', 'matched_at'),
    )
