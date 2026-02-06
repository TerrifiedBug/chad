"""Service for calling enrichment webhooks with caching and circuit breaker."""

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.encryption import decrypt
from app.core.redis import get_redis
from app.models.enrichment_webhook import EnrichmentWebhook, IndexPatternEnrichmentWebhook
from app.services.webhooks import sanitize_webhook_url

logger = logging.getLogger(__name__)


# Circuit breaker settings (fixed for v1)
CIRCUIT_FAILURE_THRESHOLD = 5  # failures before opening circuit
CIRCUIT_RECOVERY_TIMEOUT = 60  # seconds before trying again


# Semaphores per webhook to limit concurrent calls
_webhook_semaphores: dict[UUID, asyncio.Semaphore] = {}


def _get_semaphore(webhook_id: UUID, max_concurrent: int) -> asyncio.Semaphore:
    """Get or create a semaphore for rate limiting a webhook."""
    if webhook_id not in _webhook_semaphores:
        _webhook_semaphores[webhook_id] = asyncio.Semaphore(max_concurrent)
    return _webhook_semaphores[webhook_id]


# --- Circuit Breaker ---


async def _get_circuit_state(webhook_id: UUID) -> dict:
    """Get circuit breaker state from Redis."""
    redis = await get_redis()
    key = f"enrichment:circuit:{webhook_id}"
    data = await redis.get(key)
    if data:
        return json.loads(data)
    return {"state": "closed", "failures": 0, "last_failure": None}


async def _set_circuit_state(webhook_id: UUID, state: dict) -> None:
    """Set circuit breaker state in Redis."""
    redis = await get_redis()
    key = f"enrichment:circuit:{webhook_id}"
    await redis.setex(key, 300, json.dumps(state))  # Expire after 5 min of inactivity


async def _record_failure(webhook_id: UUID) -> None:
    """Record a webhook failure, potentially opening the circuit."""
    state = await _get_circuit_state(webhook_id)
    state["failures"] = state.get("failures", 0) + 1
    state["last_failure"] = datetime.now(UTC).isoformat()

    if state["failures"] >= CIRCUIT_FAILURE_THRESHOLD:
        state["state"] = "open"
        logger.warning(
            "Circuit opened for webhook %s after %d failures",
            webhook_id, state["failures"]
        )

    await _set_circuit_state(webhook_id, state)


async def _record_success(webhook_id: UUID) -> None:
    """Record a webhook success, closing the circuit."""
    await _set_circuit_state(
        webhook_id,
        {"state": "closed", "failures": 0, "last_failure": None}
    )


async def _is_circuit_open(webhook_id: UUID) -> bool:
    """Check if circuit is open (should skip calls)."""
    state = await _get_circuit_state(webhook_id)

    if state["state"] == "closed":
        return False

    if state["state"] == "open":
        # Check if recovery timeout has passed
        if state.get("last_failure"):
            last_failure = datetime.fromisoformat(state["last_failure"])
            elapsed = (datetime.now(UTC) - last_failure).total_seconds()
            if elapsed >= CIRCUIT_RECOVERY_TIMEOUT:
                # Transition to half-open, allow one probe
                state["state"] = "half-open"
                await _set_circuit_state(webhook_id, state)
                return False
        return True

    # half-open: allow the probe
    return False


# --- Caching ---


async def _get_cached_enrichment(namespace: str, lookup_value: str) -> dict | None:
    """Get cached enrichment data if available."""
    redis = await get_redis()
    key = f"enrichment:{namespace}:{lookup_value}"
    data = await redis.get(key)
    if data:
        return json.loads(data)
    return None


async def _set_cached_enrichment(
    namespace: str,
    lookup_value: str,
    data: dict,
    ttl: int
) -> None:
    """Cache enrichment data."""
    if ttl <= 0:
        return
    redis = await get_redis()
    key = f"enrichment:{namespace}:{lookup_value}"
    await redis.setex(key, ttl, json.dumps(data))


async def get_enabled_enrichment_webhooks(
    db: AsyncSession,
    index_pattern_id: UUID,
    is_ioc_alert: bool = False,
) -> list[tuple[EnrichmentWebhook, str]]:
    """
    Get enabled enrichment webhooks for an index pattern.

    Returns list of (webhook, field_to_send) tuples.
    """
    result = await db.execute(
        select(IndexPatternEnrichmentWebhook)
        .options(selectinload(IndexPatternEnrichmentWebhook.webhook))
        .where(
            IndexPatternEnrichmentWebhook.index_pattern_id == index_pattern_id,
            IndexPatternEnrichmentWebhook.is_enabled == True,  # noqa: E712
        )
    )
    configs = result.scalars().all()

    # Filter to active webhooks only, respecting IOC toggle
    return [
        (c.webhook, c.field_to_send)
        for c in configs
        if c.webhook.is_active and (not is_ioc_alert or c.webhook.include_ioc_alerts)
    ]


def _extract_field_value(doc: dict, field_path: str) -> Any:
    """Extract a value from a nested document using dot notation."""
    parts = field_path.split(".")
    current = doc
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


async def call_enrichment_webhook(
    webhook: EnrichmentWebhook,
    field_to_send: str,
    alert_id: str,
    rule_id: str,
    rule_title: str,
    severity: str,
    log_document: dict,
) -> tuple[str, dict | None, dict]:
    """
    Call a single enrichment webhook with caching and circuit breaker.

    Returns (namespace, enrichment_data or None, status_dict)
    """
    namespace = webhook.namespace
    lookup_value = _extract_field_value(log_document, field_to_send)
    lookup_str = str(lookup_value) if lookup_value else ""

    # Check cache first (if TTL > 0)
    if webhook.cache_ttl_seconds > 0 and lookup_str:
        cached = await _get_cached_enrichment(namespace, lookup_str)
        if cached is not None:
            return namespace, cached, {
                "status": "success",
                "source": "cache",
                "completed_at": datetime.now(UTC).isoformat(),
            }

    # Check circuit breaker
    if await _is_circuit_open(webhook.id):
        return namespace, None, {
            "status": "circuit_open",
            "error": "Webhook circuit is open due to repeated failures",
            "completed_at": datetime.now(UTC).isoformat(),
        }

    # Build payload
    payload = {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "rule_title": rule_title,
        "severity": severity,
        "lookup_field": field_to_send,
        "lookup_value": lookup_value,
        "log_document": log_document,
    }

    # Validate URL
    sanitized_url, error_msg = sanitize_webhook_url(webhook.url)
    if sanitized_url is None:
        logger.warning(
            "Enrichment webhook URL blocked for %s: SSRF protection",
            namespace,
        )
        return namespace, None, {
            "status": "failed",
            "error": "URL blocked by SSRF protection",
            "completed_at": datetime.now(UTC).isoformat(),
        }

    # Build headers
    headers = {"Content-Type": "application/json"}
    if webhook.header_name and webhook.header_value_encrypted:
        try:
            headers[webhook.header_name] = decrypt(webhook.header_value_encrypted)
        except Exception:
            logger.error("Failed to decrypt credentials for webhook %s", namespace)
            return namespace, None, {
                "status": "failed",
                "error": "Failed to decrypt credentials",
                "completed_at": datetime.now(UTC).isoformat(),
            }

    # Rate limit using semaphore
    semaphore = _get_semaphore(webhook.id, webhook.max_concurrent_calls)

    async with semaphore:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=webhook.method,
                    url=sanitized_url,
                    json=payload,
                    headers=headers,
                    timeout=webhook.timeout_seconds,
                )

            # Handle response
            if response.status_code == 204:
                # No content - success with empty data
                return namespace, {}, {
                    "status": "success",
                    "completed_at": datetime.now(UTC).isoformat(),
                }

            if response.status_code == 404:
                # Not found - treat as success with no data
                return namespace, {}, {
                    "status": "success",
                    "completed_at": datetime.now(UTC).isoformat(),
                }

            if response.status_code >= 400:
                error_msg_detail = f"HTTP {response.status_code}"
                try:
                    error_body = response.json()
                    if "error" in error_body:
                        error_msg_detail = str(error_body["error"])[:200]
                except Exception:
                    # Response body isn't valid JSON or lacks error field - use HTTP status
                    pass

                logger.warning(
                    "Enrichment webhook %s returned error: %s",
                    namespace,
                    response.status_code,
                )
                await _record_failure(webhook.id)
                return namespace, None, {
                    "status": "failed",
                    "error": error_msg_detail,
                    "completed_at": datetime.now(UTC).isoformat(),
                }

            # Success - parse response
            try:
                enrichment_data = response.json()
                if not isinstance(enrichment_data, dict):
                    raise ValueError("Response must be a JSON object")
            except Exception as e:
                logger.warning(
                    "Enrichment webhook %s returned invalid JSON: %s",
                    namespace,
                    type(e).__name__,
                )
                return namespace, None, {
                    "status": "invalid_response",
                    "error": "Response is not a valid JSON object",
                    "completed_at": datetime.now(UTC).isoformat(),
                }

            # Success - cache result and reset circuit breaker
            await _record_success(webhook.id)
            if webhook.cache_ttl_seconds > 0 and lookup_str:
                await _set_cached_enrichment(
                    namespace, lookup_str, enrichment_data, webhook.cache_ttl_seconds
                )

            return namespace, enrichment_data, {
                "status": "success",
                "completed_at": datetime.now(UTC).isoformat(),
            }

        except httpx.TimeoutException:
            logger.warning("Enrichment webhook %s timed out", namespace)
            await _record_failure(webhook.id)
            return namespace, None, {
                "status": "timeout",
                "error": f"Request timed out after {webhook.timeout_seconds}s",
                "completed_at": datetime.now(UTC).isoformat(),
            }
        except Exception as e:
            logger.error(
                "Enrichment webhook %s failed: %s",
                namespace,
                type(e).__name__,
            )
            await _record_failure(webhook.id)
            return namespace, None, {
                "status": "failed",
                "error": str(e)[:200],
                "completed_at": datetime.now(UTC).isoformat(),
            }


async def enrich_alert_with_webhooks(
    db: AsyncSession,
    index_pattern_id: UUID,
    alert_id: str,
    rule_id: str,
    rule_title: str,
    severity: str,
    log_document: dict,
    is_ioc_alert: bool = False,
) -> tuple[dict, dict]:
    """
    Call all enabled enrichment webhooks for an alert.

    Returns (enrichment_data, enrichment_status) dicts.
    """
    webhooks = await get_enabled_enrichment_webhooks(db, index_pattern_id, is_ioc_alert=is_ioc_alert)

    if not webhooks:
        return {}, {}

    # Call webhooks concurrently
    tasks = [
        call_enrichment_webhook(
            webhook=webhook,
            field_to_send=field_to_send,
            alert_id=alert_id,
            rule_id=rule_id,
            rule_title=rule_title,
            severity=severity,
            log_document=log_document,
        )
        for webhook, field_to_send in webhooks
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    enrichment_data = {}
    enrichment_status = {}

    for result in results:
        if isinstance(result, Exception):
            logger.error("Enrichment task failed with exception: %s", result)
            continue

        namespace, data, status = result
        enrichment_status[namespace] = status
        if data is not None:
            enrichment_data[namespace] = data

    return enrichment_data, enrichment_status
