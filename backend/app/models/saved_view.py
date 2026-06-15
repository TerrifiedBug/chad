"""Saved views — named, reusable filter presets for alert/rule lists.

A saved view captures a set of list filters (status, severity, owner, search,
etc.) under a name so analysts stop re-typing them and teams can share a common
triage cockpit. Views are owned by a user; a view marked ``is_shared`` is also
visible to everyone on the owner's team (or globally when the owner has no team),
mirroring the resource-scoping rules in :mod:`app.services.team_scope`.

The filter payload is stored opaquely as JSON: the backend never interprets it,
it just round-trips whatever the list page persists, so adding a new filter on
the frontend never needs a migration here.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class SavedView(Base, UUIDMixin, TimestampMixin):
    """A named, reusable set of list filters for a given resource type."""

    __tablename__ = "saved_views"
    __table_args__ = (
        # A user can't have two views with the same name for the same resource.
        UniqueConstraint("owner_id", "resource", "name", name="uq_saved_view_owner_resource_name"),
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    """Human label shown in the views menu."""

    resource: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """Which list this view applies to: alerts | ioc_matches | rules | correlation."""

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    """User who created and owns this view."""

    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )
    """Owner's team at creation time; used to scope shared visibility."""

    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """When true, visible to the owner's team (or globally if no team)."""

    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """When true, this is the owner's auto-applied view for the resource."""

    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    """Opaque filter payload round-tripped to the list page."""

    owner: Mapped[User] = relationship("User", foreign_keys=[owner_id], lazy="selectin")
