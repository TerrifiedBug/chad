"""Organization (tenant) model for multi-tenant / MSSP deployments.

An Organization is the top-level tenant boundary above Teams. Users, teams, and
team-ownable resources carry an ``organization_id``; per-request org scoping
(see app.core.org_context + app.services.org_scope) restricts what each request
can read/write. OSS installs run as the single DEFAULT org and see no change.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class Organization(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False, index=True)
    """DNS-safe tenant slug; resolved from ``<slug>.host`` for per-org routing."""

    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="standard")

    # Lifecycle: suspended (read-mostly, risky ops gated off) / soft-deleted.
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
