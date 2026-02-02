"""
System log model for operational error/warning tracking.
"""

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class SystemLog(Base, UUIDMixin, TimestampMixin):
    """Operational system log entry."""

    __tablename__ = "system_logs"

    # timestamp is when the event occurred (separate from created_at which is when the record was stored)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(10), nullable=False, index=True)  # ERROR, WARNING
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("idx_system_logs_timestamp_desc", timestamp.desc()),
    )
