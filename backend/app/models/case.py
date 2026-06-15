"""Case management — investigation workspace models.

A Case groups related alerts into one investigation with an owner, status,
severity, an append-only timeline, free-text comments, and an optional SLA. It
turns CHAD's alert firehose into the unit analysts actually work.

Models:
  - Case          : the investigation (status/severity/owner/SLA + sequential number)
  - CaseAlert     : link rows attaching OpenSearch alerts to a case
  - CaseEvent     : append-only timeline (status changes, links, assignments, notes)
  - CaseComment   : threaded free-text discussion (soft-deletable, like alert comments)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class CaseStatus(str, Enum):
    """Investigation lifecycle. open → investigating → contained → closed."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


# Statuses that count as "done" (SLA stops, closed_at set).
CLOSED_STATUSES = {CaseStatus.CLOSED.value}


class CaseEventType(str, Enum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    ALERT_LINKED = "alert_linked"
    ALERT_UNLINKED = "alert_unlinked"
    SEVERITY_CHANGED = "severity_changed"
    NOTE = "note"
    COMMENT = "comment"
    CLOSED = "closed"
    REOPENED = "reopened"


class Case(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "cases"

    number: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True, index=True)
    """Human-friendly sequential case number (CASE-{number})."""

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=CaseStatus.OPEN.value, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")

    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    """Analyst currently responsible for the investigation."""

    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True, index=True
    )
    """Owning team (resource scoping, mirrors rules/alerts)."""

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(nullable=False, default=False)

    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    owner: Mapped[User | None] = relationship("User", foreign_keys=[owner_id], lazy="selectin")


class CaseAlert(Base):
    """A link attaching an OpenSearch alert (by id) to a case."""

    __tablename__ = "case_alerts"
    __table_args__ = (UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Denormalised snapshot so the case still shows context if the alert ages out.
    alert_title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    alert_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CaseEvent(Base):
    """Append-only timeline entry for a case."""

    __tablename__ = "case_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    actor: Mapped[User | None] = relationship("User", foreign_keys=[actor_id], lazy="selectin")


class CaseComment(Base):
    """Free-text discussion on a case (soft-deletable)."""

    __tablename__ = "case_comments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User", foreign_keys=[user_id], lazy="selectin")
