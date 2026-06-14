"""Durable queue for one-way git config-as-code sync (Feature C).

Each row is a pending push (or delete) of one deployed rule's YAML to an
environment's git repo. A leader-elected scheduler task drains the queue with
bounded retries, so a transient git/network failure never blocks or fails a
deploy — the deploy completes, the commit catches up.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class GitSyncJob(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "git_sync_jobs"

    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("environments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SET NULL: a delete job must outlive its rule (we still need to git-rm the
    # file by its stored path after the Rule row is gone).
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    # "commit" (upsert file) | "delete" (git rm file).
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    # Repo-relative path, e.g. ``production/suspicious-powershell.yml``.
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    # Serialized rule YAML for commit jobs (null for delete jobs).
    yaml_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_message: Mapped[str] = mapped_column(Text, nullable=False)
    author_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    author_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    # pending | running | done | failed
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
