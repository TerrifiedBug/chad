"""ATT&CK technique and rule mapping models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    pass


class AttackTechnique(Base):
    """MITRE ATT&CK Enterprise technique cached from STIX data."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g., "T1059", "T1059.001"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., "TA0002"
    tactic_name: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "Execution"
    parent_id: Mapped[str | None] = mapped_column(String(20), nullable=True)  # For sub-techniques
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    platforms: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # ["Windows", "Linux", "macOS"]
    data_sources: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship to rule mappings
    rule_mappings: Mapped[list[RuleAttackMapping]] = relationship(
        "RuleAttackMapping", back_populates="technique", cascade="all, delete-orphan"
    )


class RuleAttackMapping(Base):
    """Join table linking rules to ATT&CK techniques via tag parsing."""

    __tablename__ = "rule_attack_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    technique: Mapped[AttackTechnique] = relationship("AttackTechnique", back_populates="rule_mappings")

    __table_args__ = (
        UniqueConstraint("rule_id", "technique_id", name="uq_rule_attack_mapping"),
    )
