import secrets

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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
    )  # DEPRECATED: Latency threshold in ms (default: 1000)
    health_detection_latency_warning: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=2000
    )  # Detection latency warning threshold in ms
    health_detection_latency_critical: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=10000
    )  # Detection latency critical threshold in ms
    health_opensearch_latency_warning: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=1000
    )  # OpenSearch query latency warning threshold in ms
    health_opensearch_latency_critical: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=5000
    )  # OpenSearch query latency critical threshold in ms
    health_alerting_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # GeoIP enrichment fields (e.g., ["source.ip", "destination.ip"])
    geoip_fields: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list, server_default="{}"
    )

    # Threat Intelligence enrichment config per source
    # Format: {"virustotal": {"enabled": true, "fields": ["source.ip"]}, ...}
    ti_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)

    # IP allowlist for log shipping - restrict which IPs can ship logs
    # Format: ["10.10.40.1", "10.10.40.0/24"] - supports IPs and CIDR ranges
    # None = allow all IPs (no restriction)
    allowed_ips: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Rate limiting for log shipping
    rate_limit_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    rate_limit_requests_per_minute: Mapped[int | None] = mapped_column(Integer, nullable=True, default=100)
    rate_limit_events_per_minute: Mapped[int | None] = mapped_column(Integer, nullable=True, default=50000)

    # Relationships
    field_mappings = relationship(
        "FieldMapping", back_populates="index_pattern", cascade="all, delete-orphan"
    )
    health_suppressions = relationship(
        "HealthAlertSuppression", back_populates="index_pattern", cascade="all, delete-orphan"
    )
