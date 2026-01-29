from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.index_pattern import IndexPattern
    from app.models.rule_comment import RuleComment
    from app.models.rule_exception import RuleException
    from app.models.user import User


class RuleStatus(str, Enum):
    DEPLOYED = "deployed"      # Active in percolator, matching logs
    UNDEPLOYED = "undeployed"  # Not in percolator, not matching
    SNOOZED = "snoozed"        # In percolator but alerts suppressed


class RuleSource(str, Enum):
    USER = "user"
    SIGMAHQ = "sigmahq"


class SigmaHQType(str, Enum):
    DETECTION = "detection"
    THREAT_HUNTING = "threat_hunting"
    EMERGING_THREATS = "emerging_threats"


class Rule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rules"

    title: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    status: Mapped[RuleStatus] = mapped_column(
        SAEnum(RuleStatus, values_callable=lambda e: [m.value for m in e]),
        default=RuleStatus.UNDEPLOYED
    )
    snooze_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    snooze_indefinite: Mapped[bool] = mapped_column(Boolean, default=False)

    # Deployment tracking
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Source tracking
    source: Mapped[RuleSource] = mapped_column(String(50), default=RuleSource.USER)
    sigmahq_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sigmahq_type: Mapped[SigmaHQType | None] = mapped_column(String(50), nullable=True)

    # Threshold alerting configuration
    threshold_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    threshold_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threshold_window_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threshold_group_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    index_pattern_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("index_patterns.id"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    # Relationships
    index_pattern: Mapped[IndexPattern] = relationship("IndexPattern")
    creator: Mapped[User] = relationship("User")
    versions: Mapped[list[RuleVersion]] = relationship(
        "RuleVersion", back_populates="rule", order_by="desc(RuleVersion.version_number)",
        cascade="all, delete-orphan", passive_deletes=True
    )
    exceptions: Mapped[list[RuleException]] = relationship(
        "RuleException", back_populates="rule", cascade="all, delete-orphan"
    )
    comments: Mapped[list[RuleComment]] = relationship(
        "RuleComment", cascade="all, delete-orphan", passive_deletes=True
    )


class RuleVersion(Base, UUIDMixin):
    __tablename__ = "rule_versions"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    change_reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    rule: Mapped[Rule] = relationship("Rule", back_populates="versions")
    author: Mapped[User] = relationship("User")
