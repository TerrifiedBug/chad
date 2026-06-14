"""Environment + per-environment deployment binding (Model B).

An ``Environment`` is a user-created, team-owned scope for rule *deployments*
(e.g. Production, Dev). Model B keeps ONE rule identity (a single ``Rule`` row +
unified ``RuleVersion`` history); a rule is deployed *into* an environment via a
``RuleEnvironmentDeployment`` binding rather than being copied per environment.

Back-compat: the default environment behaves exactly like today. Its deployments
also mirror into the scalar ``Rule.deployed_*``/``status`` columns and use the
legacy ``chad-percolator-{pattern}`` namespace (no re-index of live detection).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


def environment_slug(name: str) -> str:
    """Filesystem/index-safe slug for an environment name.

    Lowercased, non-alphanumerics collapsed to single hyphens, trimmed. Used to
    build the per-env percolator namespace when no explicit
    ``opensearch_index_prefix`` is set.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return slug or "env"


class Environment(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "environments"
    __table_args__ = (
        # A team cannot have two environments with the same name; global envs
        # (team_id NULL) are likewise unique by name among global envs.
        UniqueConstraint("team_id", "name", name="uq_environments_team_name"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    require_deploy_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # Optional explicit percolator/index namespace prefix; when null a slug of
    # ``name`` is used for non-default envs.
    opensearch_index_prefix: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    color: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Owning team (nullable = global / un-owned). SET NULL so deleting a team
    # un-teams its environments rather than cascading.
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )

    @property
    def slug(self) -> str:
        """Effective namespace slug (explicit prefix wins over name-derived)."""
        if self.opensearch_index_prefix:
            return environment_slug(self.opensearch_index_prefix)
        return environment_slug(self.name)


class RuleEnvironmentDeployment(Base, UUIDMixin, TimestampMixin):
    """Per-(rule, environment) deployment binding.

    Generalizes the scalar ``Rule.deployed_*``/``status`` into one row per
    environment a rule is deployed into. The default environment's binding is
    kept in sync with the scalar columns for back-compat.
    """

    __tablename__ = "rule_environment_deployments"
    __table_args__ = (
        UniqueConstraint(
            "rule_id", "environment_id", name="uq_rule_environment_deployment"
        ),
        Index("ix_rule_environment_deployments_environment_id", "environment_id"),
        Index("ix_rule_environment_deployments_rule_id", "rule_id"),
    )

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("environments.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Pinned deployed version + when. Null = not currently deployed in this env.
    deployed_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Reuses RuleStatus values (deployed/undeployed/snoozed) but stored as a
    # plain string so the per-env binding never collides with the rules enum.
    status: Mapped[str] = mapped_column(String(50), default="undeployed", nullable=False)
    snooze_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    snooze_indefinite: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
