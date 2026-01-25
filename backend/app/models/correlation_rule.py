"""Correlation rule model."""

from uuid import UUID as PyUUID

from sqlalchemy import String, Integer, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class CorrelationRule(Base, UUIDMixin, TimestampMixin):
    """A correlation rule linking two detection rules."""

    __tablename__ = "correlation_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_a_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False)
    rule_b_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False)
    entity_field: Mapped[str] = mapped_column(String(100), nullable=False)
    time_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[PyUUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Relationships
    rule_a = relationship("Rule", foreign_keys=[rule_a_id])
    rule_b = relationship("Rule", foreign_keys=[rule_b_id])
