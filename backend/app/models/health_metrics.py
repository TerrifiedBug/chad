"""Per-index health metrics for monitoring."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class IndexHealthMetrics(Base, UUIDMixin):
    """Time-series health metrics per index pattern."""

    __tablename__ = "index_health_metrics"

    index_pattern_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("index_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Ingestion metrics
    logs_received: Mapped[int] = mapped_column(Integer, default=0)
    logs_processed: Mapped[int] = mapped_column(Integer, default=0)
    logs_errored: Mapped[int] = mapped_column(Integer, default=0)
    queue_depth: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    # Detection metrics
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)
    rules_triggered: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_health_metrics_pattern_time", "index_pattern_id", "timestamp"),
    )
