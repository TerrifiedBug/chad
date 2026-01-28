"""Correlation rule model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID as PyUUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class CorrelationRule(Base, UUIDMixin, TimestampMixin):
    """A correlation rule linking two detection rules."""

    __tablename__ = "correlation_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_a_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False)
    rule_b_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False)
    entity_field: Mapped[str] = mapped_column(String(100), nullable=False)
    time_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    created_by: Mapped[PyUUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Deployment tracking
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Version tracking
    current_version: Mapped[int] = mapped_column(Integer, default=1)

    # Relationships
    rule_a = relationship("Rule", foreign_keys=[rule_a_id])
    rule_b = relationship("Rule", foreign_keys=[rule_b_id])
    creator: Mapped[User | None] = relationship("User", foreign_keys=[created_by])
    versions: Mapped[list[CorrelationRuleVersion]] = relationship(
        "CorrelationRuleVersion",
        back_populates="correlation_rule",
        order_by="desc(CorrelationRuleVersion.version_number)",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def needs_redeploy(self) -> bool:
        """Check if the rule has changes that need to be redeployed."""
        if self.deployed_version is None:
            return False
        return self.current_version > self.deployed_version


class CorrelationRuleVersion(Base, UUIDMixin):
    """Version history for correlation rules."""

    __tablename__ = "correlation_rule_versions"

    correlation_rule_id: Mapped[PyUUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("correlation_rules.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)

    # Versioned fields - snapshot of the rule at this version
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_a_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_b_id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_field: Mapped[str] = mapped_column(String(100), nullable=False)
    time_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Change tracking
    changed_by: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    change_reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    correlation_rule: Mapped[CorrelationRule] = relationship("CorrelationRule", back_populates="versions")
    author: Mapped[User] = relationship("User")
