"""Audit hardening — retention, SIEM forwarding, and PII redaction.

Three operator controls layered on the existing tamper-evident audit log:

- **Retention**: a scheduled purge deletes ``audit_log`` rows older than a
  configurable horizon (0 = keep forever) so the table can't grow unbounded.
- **SIEM forward**: ship new audit events to an external collector (webhook,
  JSON or CEF) past a stored cursor, so the audit trail lands in the org's SIEM
  for long-term retention and correlation. URL is SSRF-validated.
- **PII redaction**: redact configured field names from an event's ``details``
  before it leaves CHAD (exports + forwards), so analyst emails / usernames /
  IPs aren't spilled to a downstream system or a CSV.

All three are off by default; enabling them is an admin action.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.services.settings import get_setting, set_setting

logger = logging.getLogger(__name__)

AUDIT_SETTINGS_KEY = "audit_hardening"
_FORWARD_CURSOR_KEY = "audit_forward_cursor"

# Default PII field names redacted when redaction is enabled.
DEFAULT_PII_FIELDS = ["email", "user_email", "username", "ip", "ip_address", "name"]

DEFAULT_AUDIT_SETTINGS: dict[str, Any] = {
    "retention_days": 0,  # 0 = keep forever
    "forward": {
        "enabled": False,
        "format": "json",  # json | cef
        "url": None,
        "header_name": None,
        "header_value": None,  # stored encrypted by the API layer
    },
    "redaction": {
        "enabled": False,
        "fields": DEFAULT_PII_FIELDS,
    },
}

REDACTED = "[REDACTED]"


def merge_audit_settings(stored: dict | None) -> dict[str, Any]:
    """Overlay stored values onto defaults so missing keys stay valid."""
    out = {
        "retention_days": int(DEFAULT_AUDIT_SETTINGS["retention_days"]),
        "forward": dict(DEFAULT_AUDIT_SETTINGS["forward"]),
        "redaction": dict(DEFAULT_AUDIT_SETTINGS["redaction"]),
    }
    if not stored:
        return out
    if "retention_days" in stored:
        try:
            out["retention_days"] = max(0, int(stored["retention_days"]))
        except (TypeError, ValueError):
            pass
    if isinstance(stored.get("forward"), dict):
        out["forward"].update({k: stored["forward"][k] for k in stored["forward"]})
    if isinstance(stored.get("redaction"), dict):
        out["redaction"].update({k: stored["redaction"][k] for k in stored["redaction"]})
    if not out["redaction"].get("fields"):
        out["redaction"]["fields"] = DEFAULT_PII_FIELDS
    return out


async def get_audit_settings(db: AsyncSession) -> dict[str, Any]:
    return merge_audit_settings(await get_setting(db, AUDIT_SETTINGS_KEY))


async def save_audit_settings(db: AsyncSession, settings: dict[str, Any]) -> dict[str, Any]:
    merged = merge_audit_settings(settings)
    await set_setting(db, AUDIT_SETTINGS_KEY, merged)
    return merged


def redact_pii(details: dict | None, fields: list[str]) -> dict | None:
    """Recursively replace any key in ``fields`` with ``[REDACTED]``.

    Case-insensitive on key names. Returns a new structure; the input is not
    mutated (so the stored audit row is never altered, only the exported copy).
    """
    if details is None:
        return None
    lowered = {f.lower() for f in fields}

    def _walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: (REDACTED if k.lower() in lowered else _walk(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    return _walk(details)


def to_cef(log: AuditLog, redacted_details: dict | None) -> str:
    """Render an audit event as an ArcSight CEF line (common SIEM ingest format)."""
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    ext_parts = [
        f"act={log.action}",
        f"resourceType={log.resource_type}",
    ]
    if log.resource_id:
        ext_parts.append(f"resourceId={log.resource_id}")
    if log.ip_address:
        ext_parts.append(f"src={log.ip_address}")
    if log.user_id:
        ext_parts.append(f"suser={log.user_id}")
    ext_parts.append(f"rt={log.created_at.isoformat()}")
    if redacted_details:
        # Flatten one level for CEF custom strings; keep it bounded.
        flat = "&".join(f"{k}={v}" for k, v in list(redacted_details.items())[:10])
        ext_parts.append(f"cs1Label=details cs1={flat}")
    extension = " ".join(ext_parts)
    return f"CEF:0|CHAD|CHAD|1|{log.action}|{log.action}|3|{extension}"


def event_to_json(log: AuditLog, redacted_details: dict | None) -> dict[str, Any]:
    return {
        "id": str(log.id),
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "user_id": str(log.user_id) if log.user_id else None,
        "ip_address": log.ip_address,
        "details": redacted_details,
        "created_at": log.created_at.isoformat(),
    }


async def purge_old_audit_logs(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Delete audit rows older than the configured retention horizon.

    No-op when retention_days is 0. Returns the number of rows deleted.
    """
    settings = await get_audit_settings(db)
    days = settings["retention_days"]
    if days <= 0:
        return 0
    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    result = await db.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
    await db.commit()
    deleted = result.rowcount or 0
    if deleted:
        logger.info("Audit retention: purged %s rows older than %s days", deleted, days)
    return deleted


async def forward_new_audit_events(
    db: AsyncSession, *, decrypt_header=None, batch_size: int = 200
) -> int:
    """Ship audit events created after the stored cursor to the SIEM target.

    Cursor (last forwarded id timestamp) lives in settings so restarts don't
    re-send. Returns the count forwarded. No-op when forwarding is disabled.
    """
    settings = await get_audit_settings(db)
    fwd = settings["forward"]
    if not fwd.get("enabled") or not fwd.get("url"):
        return 0

    cursor = await get_setting(db, _FORWARD_CURSOR_KEY)
    last_ts = None
    if cursor and cursor.get("created_at"):
        try:
            last_ts = datetime.fromisoformat(cursor["created_at"])
        except ValueError:
            last_ts = None

    stmt = select(AuditLog).order_by(AuditLog.created_at).limit(batch_size)
    if last_ts is not None:
        stmt = stmt.where(AuditLog.created_at > last_ts)
    rows = list((await db.execute(stmt)).scalars().all())
    if not rows:
        return 0

    fields = settings["redaction"]["fields"] if settings["redaction"]["enabled"] else []
    fmt = fwd.get("format", "json")
    headers = {}
    if fwd.get("header_name") and fwd.get("header_value"):
        value = fwd["header_value"]
        if decrypt_header is not None:
            try:
                value = decrypt_header(value)
            except Exception:
                pass
        headers[fwd["header_name"]] = value

    forwarded = 0
    async with httpx.AsyncClient(timeout=10.0) as client:
        for log in rows:
            details = redact_pii(log.details, fields) if fields else log.details
            try:
                if fmt == "cef":
                    resp = await client.post(
                        fwd["url"], content=to_cef(log, details),
                        headers={**headers, "Content-Type": "text/plain"},
                    )
                else:
                    resp = await client.post(
                        fwd["url"], json=event_to_json(log, details), headers=headers
                    )
                resp.raise_for_status()
                forwarded += 1
            except Exception as e:
                logger.warning("Audit forward failed at event %s: %s", log.id, e)
                break  # stop; cursor not advanced past the failure, retry next run

    if forwarded:
        await set_setting(
            db, _FORWARD_CURSOR_KEY,
            {"created_at": rows[forwarded - 1].created_at.isoformat()},
        )
    return forwarded
