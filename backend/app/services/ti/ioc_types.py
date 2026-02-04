"""IOC data types for MISP sync and detection."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """MISP attribute types for IOCs."""

    IP_DST = "ip-dst"
    IP_SRC = "ip-src"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"


@dataclass
class IOCRecord:
    """A single IOC record from MISP."""

    ioc_type: IOCType
    value: str
    misp_event_id: str
    misp_event_uuid: str
    misp_attribute_uuid: str
    threat_level: str
    tags: list[str] = field(default_factory=list)
    misp_event_info: str | None = None
    first_seen: datetime | None = None
    expires_at: datetime | None = None

    @property
    def redis_key(self) -> str:
        """Generate Redis key for this IOC."""
        return f"chad:ioc:{self.ioc_type.value}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for Redis storage."""
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "misp_event_id": self.misp_event_id,
            "misp_event_uuid": self.misp_event_uuid,
            "misp_attribute_uuid": self.misp_attribute_uuid,
            "misp_event_info": self.misp_event_info,
            "threat_level": self.threat_level,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def to_opensearch_doc(self) -> dict[str, Any]:
        """Generate OpenSearch document for indicator index."""
        return {
            "indicator.type": self.ioc_type.value,
            "indicator.value": self.value,
            "misp.event_id": self.misp_event_id,
            "misp.event_uuid": self.misp_event_uuid,
            "misp.event_info": self.misp_event_info,
            "misp.attribute_uuid": self.misp_attribute_uuid,
            "misp.threat_level": self.threat_level,
            "misp.tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
