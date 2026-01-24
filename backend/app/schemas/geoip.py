"""GeoIP settings schemas."""
from pydantic import BaseModel


class GeoIPSettings(BaseModel):
    enabled: bool = False
    has_license_key: bool = False
    database_available: bool = False
    database_info: dict | None = None
    update_interval: str = "weekly"  # weekly or monthly


class GeoIPSettingsUpdate(BaseModel):
    license_key: str | None = None
    update_interval: str | None = None
    enabled: bool | None = None


class GeoIPDownloadResponse(BaseModel):
    success: bool
    message: str | None = None
    error: str | None = None
    info: dict | None = None


class GeoIPTestResponse(BaseModel):
    ip: str
    is_public: bool
    geo: dict | None = None
