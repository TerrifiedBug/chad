"""Jira Cloud integration configuration model."""

from sqlalchemy import Boolean, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class JiraConfig(Base, UUIDMixin, TimestampMixin):
    """Jira Cloud integration settings."""

    __tablename__ = "jira_config"

    jira_url: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token_encrypted: Mapped[str] = mapped_column(String(500), nullable=False)
    default_project: Mapped[str] = mapped_column(String(50), nullable=False)
    default_issue_type: Mapped[str] = mapped_column(String(50), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Severities to create Jira tickets for (e.g., ["critical", "high"])
    alert_severities: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
