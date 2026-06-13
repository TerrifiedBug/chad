"""
Deployment approval (maker-checker / two-eye) models.

A DeploymentRequest is an immutable, reviewable request to take one or more
rule versions live in the percolator. It gates the existing deploy path when
the global ``require_deploy_approval`` flag is enabled. Each item pins the exact
rule version being deployed so a later edit invalidates the approval (stale).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class DeploymentRequestStatus(str, Enum):
    """Lifecycle states for a deployment approval request."""

    PENDING = "pending"      # Awaiting review (maker filed it)
    APPROVED = "approved"    # Checker approved; apply in progress
    APPLIED = "applied"      # Successfully written to percolator
    REJECTED = "rejected"    # Checker rejected with a note
    CANCELLED = "cancelled"  # Requester withdrew it
    STALE = "stale"          # A pinned rule changed after the request was filed
    FAILED = "failed"        # Apply raised after approval


class DeploymentRequestKind(str, Enum):
    """What kind of rule an item targets."""

    SIGMA = "sigma"
    CORRELATION = "correlation"


class DeploymentItemApplyStatus(str, Enum):
    """Per-item outcome recorded at apply time."""

    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


# Terminal states cannot transition further.
TERMINAL_STATUSES = frozenset(
    {
        DeploymentRequestStatus.APPLIED.value,
        DeploymentRequestStatus.REJECTED.value,
        DeploymentRequestStatus.CANCELLED.value,
        DeploymentRequestStatus.STALE.value,
        DeploymentRequestStatus.FAILED.value,
    }
)


class DeploymentRequest(Base, UUIDMixin, TimestampMixin):
    """A maker-checker request to deploy a batch of rule versions."""

    __tablename__ = "deployment_requests"

    # Status stored as a plain string (Python-side enum for values) to avoid
    # PostgreSQL ENUM type management, matching the RuleSource/SigmaHQType pattern.
    status: Mapped[str] = mapped_column(
        String(20),
        default=DeploymentRequestStatus.PENDING.value,
        nullable=False,
        index=True,
    )

    # Maker (who requested) and checker (who reviewed). Identity comparison of
    # these two is the self-review guard.
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    change_reason: Mapped[str] = mapped_column(Text, nullable=False)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Owning team for resource-scoped RBAC (mirrors Rule.team_id). Nullable =
    # global / un-owned.
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Forward-looking seam for multi-environment promotion (Environments, P2).
    # Inert today: no FK, never read or written by the approval flow.
    target_environment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    items: Mapped[list[DeploymentRequestItem]] = relationship(
        "DeploymentRequestItem",
        back_populates="request",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    requester: Mapped[User] = relationship("User", foreign_keys=[requested_by])
    reviewer: Mapped[User | None] = relationship("User", foreign_keys=[reviewed_by])


class DeploymentRequestItem(Base, UUIDMixin):
    """One rule (sigma or correlation) pinned to a specific version within a request."""

    __tablename__ = "deployment_request_items"

    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("deployment_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Exactly one of rule_id / correlation_rule_id is set, per `kind`.
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), nullable=True, index=True
    )
    correlation_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("correlation_rules.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Pinned snapshot: the version that was current when the request was filed.
    # rule_version_id is the sigma RuleVersion row; version_number is the
    # denormalized pin used for fast stale comparison (works for both kinds).
    rule_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rule_versions.id", ondelete="SET NULL"), nullable=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)

    kind: Mapped[str] = mapped_column(
        String(20), default=DeploymentRequestKind.SIGMA.value, nullable=False
    )

    apply_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    apply_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    request: Mapped[DeploymentRequest] = relationship("DeploymentRequest", back_populates="items")
