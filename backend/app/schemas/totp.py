"""Schemas for 2FA endpoints."""

from pydantic import BaseModel, Field


class TwoFactorSetupResponse(BaseModel):
    """Response from 2FA setup initiation."""

    qr_uri: str
    secret: str


class TwoFactorVerifyRequest(BaseModel):
    """Request to verify 2FA setup."""

    code: str = Field(..., min_length=6, max_length=6)


class TwoFactorVerifyResponse(BaseModel):
    """Response from successful 2FA verification."""

    message: str
    backup_codes: list[str]


class TwoFactorDisableRequest(BaseModel):
    """Request to disable 2FA."""

    code: str = Field(..., min_length=6, max_length=8)


class TwoFactorLoginRequest(BaseModel):
    """Request to complete 2FA login."""

    token: str
    code: str = Field(..., min_length=6, max_length=8)
