"""Team model for resource-scoped, multi-team access control.

A team owns resources (rules, index patterns). Users belong to at most one team.
Admins see everything; non-admin users are scoped to their own team's resources
plus global (un-owned) resources. See app.services.team_scope.
"""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class Team(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "teams"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
