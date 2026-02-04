"""Enrichment webhook models for custom alert enrichment."""

import re
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.index_pattern import IndexPattern


# Namespace must be alphanumeric + underscores, 1-64 chars, start with letter
NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")


class EnrichmentWebhook(Base, UUIDMixin, TimestampMixin):
    """
    Custom webhook endpoint for alert enrichment.

    Webhooks receive alert context and return enrichment data
    that gets stored under enrichment.<namespace> in the alert.
    """

    __tablename__ = "enrichment_webhooks"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    namespace: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    method: Mapped[str] = mapped_column(String(10), default="POST")

    # Auth header - stored encrypted
    header_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True, default="Authorization"
    )
    header_value_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timeouts and rate limiting
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)
    max_concurrent_calls: Mapped[int] = mapped_column(Integer, default=5)

    # Caching - 0 means no caching
    cache_ttl_seconds: Mapped[int] = mapped_column(Integer, default=0)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    index_pattern_configs: Mapped[list["IndexPatternEnrichmentWebhook"]] = relationship(
        "IndexPatternEnrichmentWebhook",
        back_populates="webhook",
        cascade="all, delete-orphan",
    )

    @validates("namespace")
    def validate_namespace(self, key: str, value: str) -> str:
        """Ensure namespace is a valid identifier."""
        if not NAMESPACE_PATTERN.match(value):
            raise ValueError(
                "Namespace must start with a letter, contain only "
                "alphanumeric characters and underscores, max 64 chars"
            )
        return value.lower()


class IndexPatternEnrichmentWebhook(Base):
    """
    Junction table linking index patterns to enrichment webhooks.

    Configures which field to send for lookup and whether enabled.
    """

    __tablename__ = "index_pattern_enrichment_webhooks"

    index_pattern_id: Mapped[bytes] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("index_patterns.id", ondelete="CASCADE"),
        primary_key=True,
    )
    enrichment_webhook_id: Mapped[bytes] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("enrichment_webhooks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    field_to_send: Mapped[str] = mapped_column(String(255), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    index_pattern: Mapped["IndexPattern"] = relationship(
        "IndexPattern", back_populates="enrichment_webhook_configs"
    )
    webhook: Mapped["EnrichmentWebhook"] = relationship(
        "EnrichmentWebhook", back_populates="index_pattern_configs"
    )
