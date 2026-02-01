"""Poll state tracking for pull mode detection."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IndexPatternPollState(Base):
    """Tracks polling state for each index pattern in pull mode."""

    __tablename__ = "index_pattern_poll_state"

    index_pattern_id: Mapped[UUID] = mapped_column(
        ForeignKey("index_patterns.id", ondelete="CASCADE"),
        primary_key=True,
    )
    last_poll_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_poll_status: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # 'success', 'error'
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.now,
    )

    # Metrics for health tracking
    total_polls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    successful_polls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_polls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_matches: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    total_events_scanned: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_poll_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    avg_poll_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Real detection latency (time from event @timestamp to alert creation)
    avg_detection_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationship
    index_pattern = relationship("IndexPattern", back_populates="poll_state")
