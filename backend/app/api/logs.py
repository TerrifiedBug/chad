"""
Log matching API - receives logs from Fluentd and matches against percolator rules.

Supports two processing modes:
- Sync (default): Logs processed immediately, returns match results
- Async (queue): Logs queued to Redis Streams, returns 202 Accepted immediately

Flow (Sync mode):
1. Fluentd sends logs: POST /api/logs/{index_suffix}
2. Backend validates auth token against index pattern
3. Backend checks IP allowlist (if configured)
4. Backend checks rate limits (if configured)
5. Backend runs percolate query against corresponding percolator index
6. For each match, create alert document
7. Store alerts in OpenSearch alerts index
8. Trigger webhook notifications (async)

Flow (Async mode - queue enabled):
1. Fluentd sends logs: POST /api/logs/{index_suffix}
2. Backend validates auth token and checks rate limits
3. Backend enqueues logs to Redis Streams
4. Returns 202 Accepted with queue depth
5. Background worker processes logs asynchronously
"""

import asyncio
import ipaddress
import logging
import secrets
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import yaml
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from opensearchpy import OpenSearch
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_opensearch_client_optional
from app.db.session import get_db
from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.models.rule_exception import RuleException
from app.services.alerts import AlertService, should_suppress_alert
from app.services.batch_percolate import batch_percolate_logs
from app.services.correlation import check_correlation
from app.services.enrichment import enrich_alert
from app.services.notification import send_alert_notification
from app.services.redis_rate_limit import check_rate_limit_redis
from app.services.settings import get_app_url
from app.services.ti.ioc_detector import IOCDetector, IOCMatch
from app.services.websocket import AlertBroadcast, manager
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


def _map_threat_level_to_severity(threat_level: str) -> str:
    """Map MISP threat level to alert severity."""
    mapping = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "undefined": "informational",
        "unknown": "informational",
    }
    return mapping.get(threat_level, "informational")


def get_settings():
    """Get application settings (for easier mocking in tests)."""
    from app.core.config import settings
    return settings


def ip_matches_allowlist(client_ip: str, allowed_ips: list[str]) -> bool:
    """
    Check if a client IP matches any entry in the allowlist.

    Supports:
    - Single IPs: "10.10.40.1"
    - CIDR ranges: "10.10.40.0/24"
    """
    if not client_ip or not allowed_ips:
        return False

    try:
        client_addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for entry in allowed_ips:
        try:
            # Check if it's a CIDR range
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if client_addr in network:
                    return True
            else:
                # Single IP
                if client_addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            # Skip invalid entries
            continue

    return False


class LogMatchResponse(BaseModel):
    logs_received: int
    matches_found: int
    alerts_created: int


class LogQueueResponse(BaseModel):
    """Response for async queue processing."""
    status: str = "queued"
    queued: int
    queue_depth: int


async def validate_log_shipping_token(
    index_suffix: str,
    authorization: str | None,
    db: AsyncSession,
    request: Request | None = None,
) -> IndexPattern:
    """
    Validate the auth token for log shipping endpoint.

    Args:
        index_suffix: The index suffix from the URL path
        authorization: The Authorization header value
        db: Database session
        request: The FastAPI request (for IP validation)

    Returns:
        The matching IndexPattern if valid

    Raises:
        HTTPException: If authentication fails or IP not allowed
    """
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token",
        )

    # Extract token from "Bearer <token>" format
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format",
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    # Look up index pattern by percolator_index
    percolator_index = f"chad-percolator-{index_suffix}"
    result = await db.execute(
        select(IndexPattern).where(IndexPattern.percolator_index == percolator_index)
    )
    pattern = result.scalar_one_or_none()

    if pattern is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
        )

    # Validate the token matches (constant-time comparison to prevent timing attacks)
    if not secrets.compare_digest(pattern.auth_token, token):
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
        )

    # Check IP allowlist if configured
    if pattern.allowed_ips and request:
        client_ip = get_client_ip(request)
        if not ip_matches_allowlist(client_ip, pattern.allowed_ips):
            logger.warning(
                "Log shipping denied: IP %s not in allowlist for %s",
                client_ip,
                pattern.name
            )
            raise HTTPException(
                status_code=403,
                detail=f"IP {client_ip} not in allowlist for this index pattern",
            )

    return pattern


async def _dispatch_alert_notifications(alerts: list[dict]) -> None:
    """
    Send alert notifications after the ingest response has been returned.

    Runs as a FastAPI BackgroundTask with its own DB session so slow external
    destinations (webhooks, Jira) never back-pressure the high-throughput push
    path. Each alert is dispatched independently; one failure must not stop the
    rest.
    """
    from app.db.session import async_session_maker

    try:
        async with async_session_maker() as db:
            app_url = await get_app_url(db)
            for alert in alerts:
                alert_id = alert["alert_id"]
                alert_url = f"{app_url}/alerts/{alert_id}" if app_url else None
                try:
                    await send_alert_notification(
                        db,
                        alert_id=UUID(alert_id) if isinstance(alert_id, str) else alert_id,
                        rule_title=alert.get("rule_title", "Unknown Rule"),
                        severity=alert.get("severity", "medium"),
                        matched_log=alert.get("log_document", {}),
                        alert_url=alert_url,
                        is_ioc=alert.get("rule_id") == "ioc-detection",
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to send notification for alert %s: %s", alert_id, e
                    )
    except Exception as e:
        logger.error("Alert notification dispatch task failed: %s", e)


async def _dispatch_deferred_enrichment(index_pattern_id, items: list[dict]) -> None:
    """Run external TI + custom-webhook enrichment after the ingest response and
    merge the results into the already-stored alert documents.

    Has its own DB + OpenSearch client (the request-scoped ones are gone by the
    time a BackgroundTask runs). Best-effort: a failure must not affect ingest.
    """
    from sqlalchemy import select

    from app.db.session import async_session_maker
    from app.services.enrichment import compute_async_enrichment
    from app.services.opensearch import get_client_from_settings

    try:
        async with async_session_maker() as db:
            ip_result = await db.execute(
                select(IndexPattern).where(IndexPattern.id == index_pattern_id)
            )
            index_pattern = ip_result.scalar_one_or_none()
            if index_pattern is None:
                return

            os_client = await get_client_from_settings(db)
            if os_client is None:
                return
            svc = AlertService(os_client)

            for item in items:
                try:
                    extra = await compute_async_enrichment(
                        db,
                        item["log_document"],
                        index_pattern,
                        alert_id=item["alert_id"],
                        rule_id=item["rule_id"],
                        rule_title=item["rule_title"],
                        severity=item["severity"],
                    )
                    if extra:
                        await asyncio.to_thread(
                            svc.merge_alert_enrichment,
                            item["alerts_index"],
                            item["alert_id"],
                            extra,
                        )
                except Exception as e:
                    logger.warning(
                        "Deferred enrichment failed for alert %s: %s", item["alert_id"], e
                    )
    except Exception as e:
        logger.error("Deferred enrichment dispatch failed: %s", e)


@router.post("/{index_suffix}", response_model=LogMatchResponse)
async def receive_logs(
    index_suffix: str,
    logs: list[dict[str, Any]],
    request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Receive logs from Fluentd and match against deployed rules.

    This endpoint requires a valid auth token associated with the index pattern.
    The token should be provided in the Authorization header: Bearer <token>

    Security features:
    - IP allowlist: Restricts which IPs can ship logs (if configured)
    - Rate limiting: Limits requests/events per minute (if configured)

    Args:
        index_suffix: The index suffix (e.g., "my-logs" for chad-percolator-my-logs)
        logs: List of log documents
        authorization: Bearer token for authentication

    Returns:
        Summary of matches found
    """
    # Check if we're in pull-only deployment mode
    settings = get_settings()
    if settings.is_pull_only:
        raise HTTPException(
            status_code=503,
            detail="Log ingestion disabled in pull-only deployment. CHAD queries OpenSearch directly.",
        )

    # Validate the auth token first and get the index pattern for enrichment config
    # This also checks IP allowlist
    index_pattern = await validate_log_shipping_token(index_suffix, authorization, db, request)

    # Check if pattern is in pull mode
    if index_pattern.mode == "pull":
        raise HTTPException(
            status_code=400,
            detail=f"Index pattern '{index_pattern.name}' is in pull mode. Logs are queried from OpenSearch, not pushed.",
        )

    # Check rate limits if enabled
    if index_pattern.rate_limit_enabled:
        max_requests = index_pattern.rate_limit_requests_per_minute or 100
        max_events = index_pattern.rate_limit_events_per_minute or 50000
        await check_rate_limit_redis(str(index_pattern.id), len(logs), max_requests, max_events)

    if os_client is None:
        raise HTTPException(
            status_code=503,
            detail="OpenSearch not configured",
        )

    percolator_index = f"chad-percolator-{index_suffix}"
    alerts_index = f"chad-alerts-{index_suffix}"

    # Check percolator index exists (offloaded — sync OpenSearch client)
    if not await asyncio.to_thread(os_client.indices.exists, index=percolator_index):
        raise HTTPException(404, f"No percolator index for {index_suffix}")

    alert_service = AlertService(os_client)
    # Ensure the alerts index exists once for this batch so per-alert create_alert
    # calls can skip the indices.exists() round trip on the hot path.
    await asyncio.to_thread(alert_service.ensure_alerts_index, alerts_index)
    total_matches = 0
    alerts_created = []
    # Sigma alerts whose slow TI/webhook enrichment is deferred to the background.
    deferred_enrichment: list[dict] = []
    # IOC-only alerts accumulated across the batch, bulk-written once after the loop.
    ioc_only_pending: list[dict] = []

    # Health metrics tracking
    logs_errored = 0
    latencies = []
    processing_errors = []

    # Cache exceptions per rule to avoid repeated DB queries
    rule_exceptions_cache: dict[str, list[dict]] = {}

    # Percolate ALL logs in a single OpenSearch call instead of one round trip
    # per log (the dominant cost at high throughput). Offloaded — sync client.
    # A batch failure is a cluster-level error, so fail the request rather than
    # silently returning zero matches; the shipper will retry the batch.
    try:
        matches_by_log = await asyncio.to_thread(
            batch_percolate_logs, os_client, percolator_index, logs
        )
    except Exception as e:
        logger.error("Batch percolate failed for %s: %s", index_suffix, e)
        raise HTTPException(503, "Percolation failed") from e

    for log_idx, log in enumerate(logs):
        # Extract timestamp early for latency calculation
        log_timestamp_str = log.get("@timestamp")
        log_time = None

        if log_timestamp_str:
            try:
                # Parse ISO 8601 timestamp (handle Z and +00:00)
                log_time = datetime.fromisoformat(
                    log_timestamp_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError) as e:
                processing_errors.append(f"Invalid timestamp format: {e}")
                logs_errored += 1
                log_time = None
        else:
            # Missing timestamp is an error
            processing_errors.append("Log missing @timestamp field")
            logs_errored += 1

        # Matches for this log from the single batch percolate above.
        matches = matches_by_log.get(log_idx, [])

        # IOC Detection for Push Mode
        ioc_matches: list[IOCMatch] = []
        if index_pattern.ioc_detection_enabled and index_pattern.ioc_field_mappings:
            try:
                detector = IOCDetector()
                ioc_matches = await detector.detect_iocs(log, index_pattern.ioc_field_mappings)
            except Exception as e:
                logger.warning("IOC detection failed for log: %s", e)

        for match in matches:
            try:
                # Only process enabled rules
                if not match.get("enabled", True):
                    continue

                rule_id = match["rule_id"]

                # Get exceptions for this rule (with caching)
                if rule_id not in rule_exceptions_cache:
                    try:
                        rule_uuid = UUID(rule_id)
                        exc_result = await db.execute(
                            select(RuleException).where(
                                RuleException.rule_id == rule_uuid,
                                RuleException.is_active.is_(True),
                            )
                        )
                        exceptions = exc_result.scalars().all()
                        rule_exceptions_cache[rule_id] = [
                            {
                                "field": e.field,
                                "operator": e.operator.value,
                                "value": e.value,
                                "is_active": e.is_active,
                            }
                            for e in exceptions
                        ]
                    except (ValueError, Exception):
                        rule_exceptions_cache[rule_id] = []

                # Check if this match should be suppressed by an exception
                if should_suppress_alert(log, rule_exceptions_cache[rule_id]):
                    continue

                # Enrich log with GeoIP + IOC-cache data inline (fast, local).
                # Slow external TI / custom-webhook enrichment is deferred to a
                # background task so it never blocks the ingest response.
                enriched_log = await enrich_alert(
                    db, log, index_pattern, skip_ti_and_webhooks=True
                )

                # Add IOC enrichment to alert if matches found
                if ioc_matches:
                    enriched_log["threat_intel"] = {
                        "ioc_matches": [m.to_dict() for m in ioc_matches],
                        "has_ioc_match": True,
                    }

                # Create alert (offloaded — sync OpenSearch index() call)
                alert = await asyncio.to_thread(
                    alert_service.create_alert,
                    alerts_index=alerts_index,
                    rule_id=rule_id,
                    rule_title=match["rule_title"],
                    severity=match["severity"],
                    tags=match.get("tags", []),
                    log_document=enriched_log,
                    ensure_index=False,
                )
                alerts_created.append(alert)
                deferred_enrichment.append({
                    "alert_id": alert["alert_id"],
                    "alerts_index": alerts_index,
                    "log_document": enriched_log,
                    "rule_id": rule_id,
                    "rule_title": match["rule_title"],
                    "severity": match["severity"],
                })
                total_matches += 1

                # Calculate end-to-end latency if we have valid timestamps
                if log_time and alert.get("created_at"):
                    try:
                        alert_timestamp_str = alert.get("created_at")
                        alert_time = datetime.fromisoformat(
                            alert_timestamp_str.replace("Z", "+00:00")
                        )
                        latency_ms = int((alert_time - log_time).total_seconds() * 1000)
                        latencies.append(latency_ms)
                    except (ValueError, AttributeError) as e:
                        processing_errors.append(f"Latency calculation warning: {e}")

                # Check for correlation triggers and create correlation alerts
                try:
                    triggered_correlations = await check_correlation(
                        db,
                        rule_id=UUID(rule_id),
                        log_document=enriched_log,
                        alert_id=alert["alert_id"],
                    )
                    if triggered_correlations:
                        for corr in triggered_correlations:
                            # Fetch MITRE tags and titles from both linked sigma rules
                            correlation_tags = ["correlation"]
                            rule_a_id = corr.get("rule_a_id")
                            rule_b_id = corr.get("rule_b_id")
                            rule_a_title = None
                            rule_b_title = None

                            if rule_a_id:
                                try:
                                    rule_a_result = await db.execute(
                                        select(Rule).where(Rule.id == UUID(rule_a_id))
                                    )
                                    rule_a = rule_a_result.scalar_one_or_none()
                                    if rule_a:
                                        rule_a_title = rule_a.title
                                        if rule_a.yaml_content:
                                            parsed = yaml.safe_load(rule_a.yaml_content)
                                            if parsed and isinstance(parsed, dict):
                                                tags = parsed.get("tags", []) or []
                                                correlation_tags.extend(tags)
                                except (ValueError, yaml.YAMLError, Exception) as e:
                                    logger.debug("Failed to extract tags from rule_a: %s", e)

                            if rule_b_id:
                                try:
                                    rule_b_result = await db.execute(
                                        select(Rule).where(Rule.id == UUID(rule_b_id))
                                    )
                                    rule_b = rule_b_result.scalar_one_or_none()
                                    if rule_b:
                                        rule_b_title = rule_b.title
                                        if rule_b.yaml_content:
                                            parsed = yaml.safe_load(rule_b.yaml_content)
                                            if parsed and isinstance(parsed, dict):
                                                tags = parsed.get("tags", []) or []
                                                correlation_tags.extend(tags)
                                except (ValueError, yaml.YAMLError, Exception) as e:
                                    logger.debug("Failed to extract tags from rule_b: %s", e)

                            # Deduplicate tags while preserving order
                            seen = set()
                            unique_tags = []
                            for tag in correlation_tags:
                                if tag not in seen:
                                    seen.add(tag)
                                    unique_tags.append(tag)

                            correlation_alert = await asyncio.to_thread(
                                alert_service.create_alert,
                                alerts_index=alerts_index,
                                rule_id=corr["correlation_rule_id"],
                                rule_title=corr["correlation_name"],
                                severity=corr.get("severity", "high"),
                                tags=unique_tags,
                                log_document={
                                    "correlation": {
                                        "correlation_rule_id": corr["correlation_rule_id"],
                                        "correlation_name": corr["correlation_name"],
                                        "first_alert_id": corr.get("first_alert_id"),
                                        "second_alert_id": corr.get("second_alert_id"),
                                        "rule_a_id": corr.get("rule_a_id"),
                                        "rule_b_id": corr.get("rule_b_id"),
                                        "rule_a_title": rule_a_title,
                                        "rule_b_title": rule_b_title,
                                        "entity_field": corr.get("entity_field"),
                                        "entity_field_type": corr.get("entity_field_type", "sigma"),
                                        "entity_value": corr.get("entity_value"),
                                        "first_triggered_at": corr.get("first_triggered_at"),
                                        "second_triggered_at": corr.get("second_triggered_at"),
                                    },
                                    "@timestamp": enriched_log.get("@timestamp"),
                                },
                                ensure_index=False,
                            )
                            alerts_created.append(correlation_alert)
                            total_matches += 1

                            try:
                                corr_broadcast = AlertBroadcast(
                                    alert_id=str(correlation_alert["alert_id"]),
                                    rule_id=corr["correlation_rule_id"],
                                    rule_title=corr["correlation_name"],
                                    severity=corr.get("severity", "high"),
                                    timestamp=correlation_alert.get("created_at", ""),
                                    matched_log={"correlation": True, **corr},
                                )
                                await manager.broadcast_alert(corr_broadcast)
                            except Exception as e:
                                logger.error("WebSocket broadcast failed for correlation alert: %s", e)

                            logger.info(
                                "Correlation alert created: %s (entity: %s)",
                                corr['correlation_name'],
                                corr.get('entity_value')
                            )
                except Exception as e:
                    logger.error("Correlation check failed: %s", e)

                # Broadcast alert via WebSocket for real-time updates
                try:
                    alert_broadcast = AlertBroadcast(
                        alert_id=str(alert["alert_id"]),
                        rule_id=rule_id,
                        rule_title=alert.get("rule_title", "Unknown Rule"),
                        severity=alert.get("severity", "medium"),
                        timestamp=alert.get("created_at", ""),
                        matched_log=enriched_log,
                    )
                    await manager.broadcast_alert(alert_broadcast)
                except Exception as e:
                    logger.warning("WebSocket broadcast failed: %s", e)

            except Exception as e:
                processing_errors.append(f"Alert creation failed for match: {str(e)}")
                logs_errored += 1
                continue

        # Accumulate IOC-only alerts (logs with IOC matches but no behavioral
        # matches). Bulk-written once after the loop so an IOC-feed match storm
        # is a single OpenSearch write instead of one index() call per match.
        if ioc_matches and not matches:
            for ioc_match in ioc_matches:
                ioc_only_pending.append({
                    "rule_id": "ioc-detection",
                    "rule_title": f"IOC Match: {ioc_match.ioc_type.value}",
                    "severity": _map_threat_level_to_severity(ioc_match.threat_level),
                    "tags": ["ioc-match", f"misp:{ioc_match.misp_event_id}"] + ioc_match.tags,
                    "log_document": {
                        **log,
                        "threat_intel": {
                            "ioc_matches": [ioc_match.to_dict()],
                            "has_ioc_match": True,
                        },
                    },
                })

    # Bulk-write the accumulated IOC-only alerts in a single OpenSearch call.
    if ioc_only_pending:
        try:
            ioc_ids = await asyncio.to_thread(
                alert_service.bulk_create_alerts,
                alerts_index,
                ioc_only_pending,
                False,  # index already ensured once above
            )
            for data, aid in zip(ioc_only_pending, ioc_ids):
                alerts_created.append({
                    "alert_id": aid,
                    "rule_id": "ioc-detection",
                    "rule_title": data["rule_title"],
                    "severity": data["severity"],
                    "log_document": data["log_document"],
                })
                total_matches += 1
        except Exception as e:
            logger.error("Failed to bulk-create IOC alerts: %s", e)

    # Dispatch notifications in the BACKGROUND so external webhook/Jira fan-out
    # never blocks the ingest response (a slow destination must not back-pressure
    # the high-throughput push path). Runs after the response with its own session.
    if alerts_created:
        notif_payload = [
            {
                "alert_id": alert["alert_id"],
                "rule_id": alert.get("rule_id"),
                "rule_title": alert.get("rule_title", "Unknown Rule"),
                "severity": alert.get("severity", "medium"),
                "log_document": alert.get("log_document", {}),
            }
            for alert in alerts_created
        ]
        background_tasks.add_task(_dispatch_alert_notifications, notif_payload)

    # Defer slow external enrichment (TI lookups + custom webhooks) off the
    # response path; it is merged into the stored alert docs afterwards.
    if deferred_enrichment:
        background_tasks.add_task(
            _dispatch_deferred_enrichment, index_pattern.id, deferred_enrichment
        )

    # Record health metrics for this batch of logs
    try:
        # Calculate average latency
        avg_latency = (
            int(sum(latencies) / len(latencies)) if latencies else 0
        )

        metric = IndexHealthMetrics(
            index_pattern_id=index_pattern.id,
            logs_received=len(logs),
            logs_processed=len(logs) - logs_errored,
            logs_errored=logs_errored,
            alerts_generated=len(alerts_created),
            rules_triggered=total_matches,
            queue_depth=0,  # TODO: Track actual queue depth from BackgroundTasks
            avg_detection_latency_ms=avg_latency,
        )
        db.add(metric)
        await db.commit()

        # Log processing errors for monitoring
        if processing_errors:
            logger.warning(
                "Batch processing had %d errors: First 3 errors: %s",
                len(processing_errors),
                processing_errors[:3]
            )

    except Exception as e:
        # Log but don't fail the request if metric recording fails
        logger.error("Failed to record health metrics: %s", e)

    return LogMatchResponse(
        logs_received=len(logs),
        matches_found=total_matches,
        alerts_created=len(alerts_created),
    )


@router.post("/{index_suffix}/test")
async def test_log_matching(
    index_suffix: str,
    log: dict[str, Any],
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Test a single log against deployed rules without creating alerts.

    This endpoint requires a valid auth token associated with the index pattern.
    The token should be provided in the Authorization header: Bearer <token>

    Useful for testing rules during development.
    Returns match results including whether exceptions would suppress the alert.
    """
    # Validate the auth token first (also checks IP allowlist)
    await validate_log_shipping_token(index_suffix, authorization, db, request)

    if os_client is None:
        raise HTTPException(
            status_code=503,
            detail="OpenSearch not configured",
        )

    percolator_index = f"chad-percolator-{index_suffix}"

    if not await asyncio.to_thread(os_client.indices.exists, index=percolator_index):
        raise HTTPException(404, f"No percolator index for {index_suffix}")

    alert_service = AlertService(os_client)
    matches = await asyncio.to_thread(alert_service.match_log, percolator_index, log)

    results = []
    for m in matches:
        rule_id = m["rule_id"]

        # Get exceptions for this rule
        suppressed = False
        matching_exception = None
        try:
            rule_uuid = UUID(rule_id)
            exc_result = await db.execute(
                select(RuleException).where(
                    RuleException.rule_id == rule_uuid,
                    RuleException.is_active.is_(True),
                )
            )
            exceptions = exc_result.scalars().all()
            exception_dicts = [
                {
                    "field": e.field,
                    "operator": e.operator.value,
                    "value": e.value,
                    "is_active": e.is_active,
                    "reason": e.reason,
                }
                for e in exceptions
            ]

            # Check if suppressed and find matching exception
            for exc in exception_dicts:
                from app.models.rule_exception import ExceptionOperator
                from app.services.alerts import check_exception_match
                if check_exception_match(log, exc["field"], ExceptionOperator(exc["operator"]), exc["value"]):
                    suppressed = True
                    matching_exception = exc
                    break
        except (ValueError, Exception) as e:
            logger.debug("Exception match check failed for rule %s: %s", rule_id, e)

        results.append({
            "rule_id": rule_id,
            "rule_title": m["rule_title"],
            "severity": m["severity"],
            "tags": m.get("tags", []),
            "enabled": m.get("enabled", True),
            "suppressed_by_exception": suppressed,
            "matching_exception": matching_exception,
        })

    return {"matches": results}


@router.post("/{index_suffix}/queue", response_model=LogQueueResponse, status_code=202)
async def receive_logs_queue(
    index_suffix: str,
    logs: list[dict[str, Any]],
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """
    Receive logs and queue for asynchronous processing.

    Returns 202 Accepted immediately. Logs are processed by background workers.
    Use this endpoint for high-volume log shipping where immediate alert creation
    is not required.

    Backpressure behavior controlled by queue_settings.backpressure_mode:
    - "drop": Accept logs, evict oldest when queue full (default)
    - "reject": Return 503 when queue is at critical threshold
    """
    # Check if we're in pull-only deployment mode
    settings = get_settings()
    if settings.is_pull_only:
        raise HTTPException(
            status_code=503,
            detail="Log ingestion disabled in pull-only deployment. CHAD queries OpenSearch directly.",
        )

    # Validate the auth token first (also checks IP allowlist)
    index_pattern = await validate_log_shipping_token(index_suffix, authorization, db, request)

    # Check if pattern is in pull mode
    if index_pattern.mode == "pull":
        raise HTTPException(
            status_code=400,
            detail=f"Index pattern '{index_pattern.name}' is in pull mode. Logs are queried from OpenSearch, not pushed.",
        )

    # Check rate limits if enabled
    if index_pattern.rate_limit_enabled:
        max_requests = index_pattern.rate_limit_requests_per_minute or 100
        max_events = index_pattern.rate_limit_events_per_minute or 50000
        await check_rate_limit_redis(str(index_pattern.id), len(logs), max_requests, max_events)

    # Get queue settings
    from app.services.queue_settings import get_queue_settings
    queue_settings = await get_queue_settings(db)

    # Get Redis client and queue service
    from app.core.redis import get_redis
    from app.services.log_queue import LogQueueService

    redis = await get_redis()
    queue_service = LogQueueService(redis, max_queue_size=queue_settings.max_queue_size)

    # Check backpressure
    current_depth = await queue_service.get_queue_depth(index_suffix)

    if current_depth >= queue_settings.critical_threshold:
        if queue_settings.backpressure_mode == "reject":
            raise HTTPException(
                status_code=503,
                detail="Queue at capacity",
                headers={"Retry-After": "30"},
            )
        # "drop" mode continues - maxlen will evict oldest

    # Queue the logs
    result = await queue_service.enqueue_logs(index_suffix, logs)

    return LogQueueResponse(
        status="queued",
        queued=result["queued"],
        queue_depth=result["queue_depth"],
    )
