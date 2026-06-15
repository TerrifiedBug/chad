"""SLA policy + breach detection for alert triage.

An SLA policy assigns each severity a target time-to-resolution (in minutes).
An alert's ``sla_due_at`` is ``created_at + target(severity)``; once that passes
while the alert is still open (status ``new``/``acknowledged``), the alert has
breached its SLA.

To keep the hot ingest path untouched, due times are computed lazily — the
frontend derives the badge from ``created_at`` + the policy, and a periodic
scheduler job (:func:`scan_sla_breaches`) stamps ``sla_breached``/``sla_due_at``
onto the OpenSearch alert document and raises an operational warning so breaches
are visible without re-reading every alert on each request.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from opensearchpy import OpenSearch
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.settings import get_setting, set_setting
from app.services.system_log import LogCategory, system_log_service

logger = logging.getLogger(__name__)

SLA_POLICY_KEY = "sla_policy"

# Severities CHAD assigns to alerts, most → least urgent.
SEVERITIES = ["critical", "high", "medium", "low", "informational"]

# Default targets in minutes. 0 means "no SLA for this severity" (never breaches).
DEFAULT_SLA_POLICY: dict[str, Any] = {
    "enabled": False,
    "targets_minutes": {
        "critical": 60,        # 1 hour
        "high": 240,           # 4 hours
        "medium": 1440,        # 1 day
        "low": 4320,           # 3 days
        "informational": 0,    # no SLA
    },
}

# Open statuses an SLA can still breach against. resolved/false_positive are done.
OPEN_STATUSES = ["new", "acknowledged"]


def merge_policy(stored: dict | None) -> dict[str, Any]:
    """Overlay a stored policy onto the defaults so missing keys stay valid."""
    policy = {
        "enabled": bool(DEFAULT_SLA_POLICY["enabled"]),
        "targets_minutes": dict(DEFAULT_SLA_POLICY["targets_minutes"]),
    }
    if not stored:
        return policy
    if "enabled" in stored:
        policy["enabled"] = bool(stored["enabled"])
    targets = stored.get("targets_minutes") or {}
    for sev in SEVERITIES:
        if sev in targets:
            try:
                policy["targets_minutes"][sev] = max(0, int(targets[sev]))
            except (TypeError, ValueError):
                pass  # keep default on malformed value
    return policy


async def get_sla_policy(db: AsyncSession) -> dict[str, Any]:
    """Return the effective SLA policy (stored values merged over defaults)."""
    return merge_policy(await get_setting(db, SLA_POLICY_KEY))


async def save_sla_policy(db: AsyncSession, policy: dict[str, Any]) -> dict[str, Any]:
    """Persist a (validated/merged) SLA policy and return the stored form."""
    merged = merge_policy(policy)
    await set_setting(db, SLA_POLICY_KEY, merged)
    return merged


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def compute_due_at(created_at: Any, severity: str, policy: dict[str, Any]) -> datetime | None:
    """Return when an alert of ``severity`` created at ``created_at`` is due.

    Returns ``None`` when the policy is disabled, the severity has a 0/missing
    target, or ``created_at`` can't be parsed — i.e. "this alert has no SLA".
    """
    if not policy.get("enabled"):
        return None
    target = policy.get("targets_minutes", {}).get((severity or "").lower(), 0)
    try:
        target = int(target)
    except (TypeError, ValueError):
        return None
    if target <= 0:
        return None
    created = _parse_dt(created_at)
    if created is None:
        return None
    return created + timedelta(minutes=target)


async def scan_sla_breaches(
    db: AsyncSession,
    os_client: OpenSearch,
    *,
    now: datetime | None = None,
    alerts_index: str = "chad-alerts-*",
    batch_size: int = 500,
) -> int:
    """Flag open alerts whose SLA has elapsed.

    Stamps ``sla_breached=true`` + ``sla_due_at`` on each newly-breached alert
    document and raises one operational warning summarising the batch. Returns
    the number of alerts newly flagged. No-op when the policy is disabled.
    """
    policy = await get_sla_policy(db)
    if not policy.get("enabled"):
        return 0

    now = now or datetime.now().astimezone()

    # Only consider open, not-already-flagged alerts to keep the scan cheap and
    # idempotent. We still recompute due per-hit since targets vary by severity.
    query = {
        "size": batch_size,
        "query": {
            "bool": {
                "must": [{"terms": {"status": OPEN_STATUSES}}],
                "must_not": [{"term": {"sla_breached": True}}],
            }
        },
        "_source": ["alert_id", "severity", "created_at", "status"],
    }

    try:
        result = os_client.search(index=alerts_index, body=query)
    except Exception as e:  # index may not exist yet on a fresh install
        logger.debug("SLA scan search failed (non-fatal): %s", e)
        return 0

    hits = result.get("hits", {}).get("hits", [])
    flagged = 0
    by_severity: dict[str, int] = {}

    for hit in hits:
        src = hit.get("_source", {})
        due = compute_due_at(src.get("created_at"), src.get("severity", ""), policy)
        if due is None or now < due:
            continue
        try:
            os_client.update(
                index=hit["_index"],
                id=hit["_id"],
                body={"doc": {"sla_breached": True, "sla_due_at": due.isoformat()}},
                refresh=False,
            )
            flagged += 1
            sev = (src.get("severity") or "unknown").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        except Exception as e:
            logger.warning("Failed to stamp SLA breach on %s: %s", hit.get("_id"), e)

    if flagged:
        await system_log_service.log_warning(
            db,
            category=LogCategory.ALERTS,
            service="sla_monitor",
            message=f"{flagged} alert(s) breached their SLA",
            details={"by_severity": by_severity},
        )
        await db.commit()

    return flagged
