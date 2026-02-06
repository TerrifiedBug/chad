"""MISP imported rule tracking model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, backref, mapped_column, relationship

from app.db.base import Base


class MISPImportedRule(Base):
    """Tracks rules imported from MISP events for update detection."""

    __tablename__ = "misp_imported_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Store connection info directly (TI config may change)
    misp_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    misp_event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    misp_event_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    misp_event_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    misp_event_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    misp_event_threat_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    ioc_count: Mapped[int] = mapped_column(Integer, nullable=False)
    ioc_values: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    misp_event_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship
    rule = relationship("Rule", backref=backref("misp_import", passive_deletes=True))
