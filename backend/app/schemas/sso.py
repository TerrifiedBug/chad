"""Pydantic schemas for multi-provider OIDC/SSO management."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Secret is masked (never echoed) on read. This sentinel marks "configured".
SECRET_MASK = "********"


class GroupMappingIn(BaseModel):
    group_value: str = Field(min_length=1, max_length=512)
    team_id: UUID | None = None
    role: str = Field(default="viewer")


class GroupMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    group_value: str
    team_id: UUID | None = None
    role: str


class SSOProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    enabled: bool = False
    issuer_url: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=512)
    # Write-only. Omitted on read; on update, omit to keep the existing secret.
    client_secret: str | None = None
    token_auth_method: str = "client_secret_post"
    scopes: str = "openid email profile"
    default_role: str = "viewer"
    default_team_id: UUID | None = None
    group_sync_enabled: bool = False
    groups_claim: str | None = None
    groups_scope: str | None = None
    role_claim: str | None = None
    admin_values: str | None = None
    analyst_values: str | None = None
    viewer_values: str | None = None
    require_email_verified: bool = True
    group_mappings: list[GroupMappingIn] | None = None


class SSOProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    issuer_url: str | None = Field(default=None, min_length=1, max_length=512)
    client_id: str | None = Field(default=None, min_length=1, max_length=512)
    client_secret: str | None = None
    token_auth_method: str | None = None
    scopes: str | None = None
    default_role: str | None = None
    default_team_id: UUID | None = None
    group_sync_enabled: bool | None = None
    groups_claim: str | None = None
    groups_scope: str | None = None
    role_claim: str | None = None
    admin_values: str | None = None
    analyst_values: str | None = None
    viewer_values: str | None = None
    require_email_verified: bool | None = None
    group_mappings: list[GroupMappingIn] | None = None


class SSOProviderResponse(BaseModel):
    """Provider as returned to admins. The secret is NEVER included; instead
    ``client_secret_set`` says whether one is configured."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    enabled: bool
    issuer_url: str
    client_id: str
    client_secret_set: bool = False
    token_auth_method: str
    scopes: str
    default_role: str
    default_team_id: UUID | None = None
    group_sync_enabled: bool
    groups_claim: str | None = None
    groups_scope: str | None = None
    role_claim: str | None = None
    admin_values: str | None = None
    analyst_values: str | None = None
    viewer_values: str | None = None
    require_email_verified: bool
    last_tested_at: datetime | None = None
    last_test_success: bool | None = None
    group_mappings: list[GroupMappingOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class SSOTestResult(BaseModel):
    success: bool
    message: str
    last_tested_at: datetime | None = None


class SSOEnforcementUpdate(BaseModel):
    sso_enforced: bool


class SSOEnforcementResponse(BaseModel):
    sso_enforced: bool
