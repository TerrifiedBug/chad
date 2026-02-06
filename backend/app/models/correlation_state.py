"""Correlation state tracking model."""

from datetime import datetime
from uuid import UUID as PyUUID

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class CorrelationState(Base, UUIDMixin):
    """Tracks partial correlation matches awaiting completion."""

    __tablename__ = "correlation_state"

    correlation_rule_id: Mapped[PyUUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("correlation_rules.id"), nullable=False
    )
    entity_value: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(100), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_correlation_lookup", "correlation_rule_id", "entity_value", "expires_at"),
    )
