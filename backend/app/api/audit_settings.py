"""Audit hardening settings API (admin only).

Configure audit retention, SIEM forwarding, and PII redaction. The forward
header value is encrypted at rest and never returned.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.user import User
from app.schemas.audit_settings import (
    AuditSettingsResponse,
    AuditSettingsUpdate,
)
from app.services.audit import audit_log
from app.services.audit_export import (
    forward_new_audit_events,
    get_audit_settings,
    save_audit_settings,
)
from app.services.webhooks import _validate_url_components
from app.utils.request import get_client_ip

router = APIRouter(prefix="/audit-settings", tags=["audit-settings"])


def _to_response(stored: dict) -> AuditSettingsResponse:
    fwd = stored["forward"]
    return AuditSettingsResponse(
        retention_days=stored["retention_days"],
        forward={
            "enabled": fwd.get("enabled", False),
            "format": fwd.get("format", "json"),
            "url": fwd.get("url"),
            "header_name": fwd.get("header_name"),
            "has_header_value": bool(fwd.get("header_value")),
        },
        redaction=stored["redaction"],
    )


@router.get("", response_model=AuditSettingsResponse)
async def read_audit_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    return _to_response(await get_audit_settings(db))


@router.put("", response_model=AuditSettingsResponse)
async def update_audit_settings(
    data: AuditSettingsUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    current = await get_audit_settings(db)
    fwd = data.forward

    if fwd.enabled:
        if not fwd.url:
            raise HTTPException(status_code=422, detail="forward.url required when enabled")
        is_valid, error_msg, _ = _validate_url_components(fwd.url)
        if not is_valid:
            raise HTTPException(status_code=422, detail=f"Invalid forward URL: {error_msg}")

    # Preserve the stored (encrypted) header value when the client doesn't send a
    # new one; encrypt a freshly provided one.
    if fwd.header_value:
        header_value = encrypt(fwd.header_value)
    else:
        header_value = current["forward"].get("header_value")

    new_settings = {
        "retention_days": data.retention_days,
        "forward": {
            "enabled": fwd.enabled,
            "format": fwd.format,
            "url": fwd.url,
            "header_name": fwd.header_name,
            "header_value": header_value,
        },
        "redaction": {
            "enabled": data.redaction.enabled,
            "fields": data.redaction.fields or current["redaction"]["fields"],
        },
    }
    stored = await save_audit_settings(db, new_settings)
    await audit_log(
        db, admin.id, "audit_settings.update", "setting", "audit_hardening",
        {"retention_days": stored["retention_days"], "forward_enabled": fwd.enabled,
         "redaction_enabled": data.redaction.enabled},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return _to_response(stored)


@router.post("/test-forward")
async def test_forward(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Forward any pending audit events now (manual flush) and report the count."""
    try:
        count = await forward_new_audit_events(db, decrypt_header=decrypt)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Forward failed: {e}") from e
    return {"forwarded": count}
