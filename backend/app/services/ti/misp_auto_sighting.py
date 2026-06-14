"""Automatic MISP sighting feedback (Feature D).

When CHAD raises an alert that matched an IOC pulled *from* MISP, we can feed a
"sighting" back to MISP ("we saw this attribute"). This closes the intel loop
without creating any new events/attributes — so it never spams a shared MISP
instance and cannot cause a pull→push→pull cycle (we only ever sight what we
already pulled).

Behaviour:
- Gated behind the ``misp_auto_push`` Setting, **default OFF**.
- Sightings only — never ``create_event``.
- Per-attribute deduplicated via Redis (``chad:misp:sighting:{uuid}``) so an
  alert storm on one IOC records a single sighting per window.
- Best-effort and non-raising: invoked after alerts are already persisted, it
  must never break ingest. Runs with no user context → audited as a system actor.
"""

import logging
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import get_redis
from app.services.audit import audit_log
from app.services.settings import get_setting

logger = logging.getLogger(__name__)

# Setting key holding ``{"enabled": bool}``. Absent/false → feature off.
MISP_AUTO_PUSH_SETTING_KEY = "misp_auto_push"

# Redis dedup guard. TTL bounds how often the same attribute is re-sighted.
_SIGHTING_DEDUP_PREFIX = "chad:misp:sighting"
_SIGHTING_DEDUP_TTL_SECONDS = 3600  # 1 hour

# Sighting source label + type (0 = sighting, 1 = false positive).
_SIGHTING_SOURCE = "CHAD"
_SIGHTING_TYPE = 0


async def is_auto_push_enabled(db: AsyncSession) -> bool:
    """True only when the operator has explicitly enabled auto-push."""
    try:
        cfg = await get_setting(db, MISP_AUTO_PUSH_SETTING_KEY)
        return bool(cfg and cfg.get("enabled") is True)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("Failed to read misp_auto_push setting: %s", e)
        return False


def extract_misp_attribute_uuids(alerts: list[dict]) -> set[str]:
    """Collect distinct MISP attribute UUIDs from the alerts' IOC matches."""
    uuids: set[str] = set()
    for alert in alerts or []:
        for match in alert.get("ioc_matches") or []:
            if not isinstance(match, dict):
                continue
            uuid = match.get("misp_attribute_uuid")
            if uuid:
                uuids.add(str(uuid))
    return uuids


async def _claim_sighting(redis, attribute_uuid: str) -> bool:
    """Reserve the dedup slot for ``attribute_uuid``.

    Returns True for the first caller in the window (record the sighting),
    False if already claimed. Fail-open on Redis error (better to risk a
    duplicate sighting than to silently drop legitimate feedback).
    """
    if redis is None:
        return True
    try:
        key = f"{_SIGHTING_DEDUP_PREFIX}:{attribute_uuid}"
        return bool(await redis.set(key, "1", nx=True, ex=_SIGHTING_DEDUP_TTL_SECONDS))
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("MISP sighting dedup check failed: %s", e)
        return True


async def record_sightings_for_alerts(db: AsyncSession, alerts: list[dict]) -> int:
    """Record MISP sightings for any MISP-sourced IOC in ``alerts``.

    No-op (returns 0) when the feature is disabled, MISP isn't configured, or no
    alert carries a ``misp_attribute_uuid``. Never raises.
    """
    if not alerts:
        return 0
    if not await is_auto_push_enabled(db):
        return 0

    uuids = extract_misp_attribute_uuids(alerts)
    if not uuids:
        return 0

    # Reuse the same feedback-service constructor as the manual push endpoint
    # rather than building a sixth MISP client.
    from app.api.misp_feedback import create_feedback_service

    try:
        service = await create_feedback_service(db)
    except Exception as e:
        # MISP not configured/enabled — silently skip (feature is opt-in).
        logger.debug("MISP auto-sighting skipped (no feedback service): %s", e)
        return 0

    try:
        redis = await get_redis()
    except Exception:
        redis = None

    recorded = 0
    now = datetime.now(UTC)
    try:
        for attribute_uuid in uuids:
            if not await _claim_sighting(redis, attribute_uuid):
                continue
            try:
                result = await service.record_sighting(
                    attribute_uuid=attribute_uuid,
                    source=_SIGHTING_SOURCE,
                    timestamp=now,
                    sighting_type=_SIGHTING_TYPE,
                )
                if result.success:
                    recorded += 1
                else:
                    logger.debug(
                        "MISP auto-sighting failed for %s: %s",
                        attribute_uuid,
                        result.error,
                    )
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("MISP auto-sighting error for %s: %s", attribute_uuid, e)
    finally:
        # create_feedback_service builds a dedicated httpx client; close it.
        client = getattr(service, "_client", None)
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                pass

    if recorded:
        logger.info(
            "Auto-recorded %d MISP sighting(s) from %d alert(s)", recorded, len(alerts)
        )
        try:
            await audit_log(
                db,
                None,  # system actor — no user context on the ingest path
                "misp.sighting.auto",
                "misp",
                None,
                {"sightings_recorded": recorded, "attributes": len(uuids)},
            )
        except Exception as e:  # pragma: no cover - audit must never break ingest
            logger.debug("Failed to audit auto-sighting: %s", e)

    return recorded
