"""Threat Intelligence source configuration model."""

import enum

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class TISourceType(str, enum.Enum):
    """Supported Threat Intelligence source types."""

    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    GREYNOISE = "greynoise"
    THREATFOX = "threatfox"
    MISP = "misp"
    ABUSE_CH = "abuse_ch"
    ALIENVAULT_OTX = "alienvault_otx"
    PHISHTANK = "phishtank"


class TISourceConfig(Base, UUIDMixin, TimestampMixin):
    """Threat Intelligence source configuration."""

    __tablename__ = "ti_source_config"

    # Source type (virustotal, abuseipdb, greynoise, threatfox, misp, abuse_ch, alienvault_otx, phishtank)
    # Stored as String, validated via Python Enum
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

    # Whether this source is enabled
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Encrypted API key for the service
    api_key_encrypted: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Instance URL (for self-hosted services like ThreatFox)
    instance_url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Additional configuration stored as JSON
    # Examples: rate limits, cache TTL, enrichment fields, etc.
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)

    # Health monitoring
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    health_check_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def source_type_enum(self) -> TISourceType | None:
        """Get source_type as enum value."""
        try:
            return TISourceType(self.source_type)
        except ValueError:
            return None

    def __repr__(self) -> str:
        return f"<TISourceConfig(source_type={self.source_type}, is_enabled={self.is_enabled})>"
