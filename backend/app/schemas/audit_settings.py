"""Schemas for audit hardening settings (retention, SIEM forward, redaction)."""

from pydantic import BaseModel, Field


class AuditForwardConfig(BaseModel):
    enabled: bool = False
    format: str = Field(default="json", pattern="^(json|cef)$")
    url: str | None = None
    header_name: str | None = None
    # Write-only: send to set/rotate; never returned. The response uses
    # has_header_value instead.
    header_value: str | None = None


class AuditForwardConfigResponse(BaseModel):
    enabled: bool
    format: str
    url: str | None = None
    header_name: str | None = None
    has_header_value: bool = False


class AuditRedactionConfig(BaseModel):
    enabled: bool = False
    fields: list[str] = Field(default_factory=list)


class AuditSettingsUpdate(BaseModel):
    retention_days: int = Field(default=0, ge=0)
    forward: AuditForwardConfig = Field(default_factory=AuditForwardConfig)
    redaction: AuditRedactionConfig = Field(default_factory=AuditRedactionConfig)


class AuditSettingsResponse(BaseModel):
    retention_days: int
    forward: AuditForwardConfigResponse
    redaction: AuditRedactionConfig
