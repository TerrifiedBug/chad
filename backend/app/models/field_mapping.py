"""Field mapping model for Sigma to log field translations."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MappingOrigin(str, enum.Enum):
    MANUAL = "MANUAL"
    AI_SUGGESTED = "AI_SUGGESTED"


class FieldMapping(Base):
    __tablename__ = "field_mappings"
    __table_args__ = (
        UniqueConstraint("index_pattern_id", "sigma_field", name="uq_mapping_scope_field"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    index_pattern_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("index_patterns.id", ondelete="CASCADE"),
        nullable=False  # Required - all mappings must be per-index
    )
    sigma_field: Mapped[str] = mapped_column(String(255), nullable=False)
    target_field: Mapped[str] = mapped_column(String(255), nullable=False)
    origin: Mapped[MappingOrigin] = mapped_column(
        Enum(MappingOrigin), nullable=False, default=MappingOrigin.MANUAL
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)  # AI confidence 0-1
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    version: Mapped[int] = mapped_column(nullable=False, default=1)

    # Relationships
    index_pattern = relationship("IndexPattern", back_populates="field_mappings")
    creator = relationship("User")
