import secrets

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


def generate_auth_token() -> str:
    """Generate a secure auth token for log shipping."""
    return secrets.token_urlsafe(32)


class IndexPattern(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "index_patterns"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    pattern: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    percolator_index: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_token: Mapped[str] = mapped_column(
        String(64), nullable=False, default=generate_auth_token
    )

    # Health alerting thresholds (nullable = use global defaults)
    health_no_data_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )  # Minutes of no data before alerting (default: 15)
    health_error_rate_percent: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )  # Error rate percentage threshold (default: 5.0)
    health_latency_ms: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )  # Latency threshold in ms (default: 1000)
    health_alerting_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # GeoIP enrichment fields (e.g., ["source.ip", "destination.ip"])
    geoip_fields: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list, server_default="{}"
    )

    # Relationships
    field_mappings = relationship(
        "FieldMapping", back_populates="index_pattern", cascade="all, delete-orphan"
    )
