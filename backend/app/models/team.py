"""Team model for resource-scoped, multi-team access control.

A team owns resources (rules, index patterns). Users belong to at most one team.
Admins see everything; non-admin users are scoped to their own team's resources
plus global (un-owned) resources. See app.services.team_scope.
"""

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class Team(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "teams"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Owning tenant (multi-tenant / MSSP); backfilled to the default org.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
