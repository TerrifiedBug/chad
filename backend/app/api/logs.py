"""
Log matching API - receives logs from Fluentd and matches against percolator rules.

Flow:
1. Fluentd sends logs: POST /api/logs/{index_suffix}
2. Backend validates auth token against index pattern
3. Backend checks IP allowlist (if configured)
4. Backend checks rate limits (if configured)
5. Backend runs percolate query against corresponding percolator index
6. For each match, create alert document
7. Store alerts in OpenSearch alerts index
8. Trigger webhook notifications (async)
"""

import ipaddress
import secrets
import time
from collections import defaultdict
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
from app.services.correlation import check_correlation
from app.services.enrichment import enrich_alert
from app.services.notification import send_alert_notification
from app.services.settings import get_app_url
from app.services.websocket import AlertBroadcast, manager

router = APIRouter(prefix="/logs", tags=["logs"])

# Rate limiting storage (in-memory, per-process)
# Format: {pattern_id: {"requests": [timestamps], "events": [(timestamp, count)]}}
rate_limits: dict[str, dict[str, list]] = defaultdict(lambda: {"requests": [], "events": []})


def get_client_ip(request: Request) -> str:
    """
    Get the client IP address from the request.

    Checks X-Forwarded-For and X-Real-IP headers first (for reverse proxy setups),
    then falls back to the direct connection IP.
    """
    # Check X-Forwarded-For first (may contain multiple IPs)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct connection
    if request.client:
        return request.client.host

    return ""


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


def check_rate_limit(pattern_id: str, event_count: int, max_requests: int, max_events: int) -> None:
    """
    Check and enforce rate limits for log shipping.

    Uses a sliding window of 60 seconds.

    Args:
        pattern_id: The index pattern ID
        event_count: Number of events in this request
        max_requests: Maximum requests per minute
        max_events: Maximum events per minute

    Raises:
        HTTPException: If rate limit is exceeded
    """
    now = time.time()
    window = 60  # 1 minute

    limits = rate_limits[pattern_id]

    # Clean old entries
    limits["requests"] = [t for t in limits["requests"] if now - t < window]
    limits["events"] = [(t, c) for t, c in limits["events"] if now - t < window]

    # Check request limit
    if len(limits["requests"]) >= max_requests:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: too many requests ({max_requests}/minute)"
        )

    # Check event limit
    total_events = sum(c for _, c in limits["events"])
    if total_events + event_count > max_events:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: too many events ({max_events}/minute)"
        )

    # Record this request
    limits["requests"].append(now)
    limits["events"].append((now, event_count))


class LogMatchResponse(BaseModel):
    logs_received: int
    matches_found: int
    alerts_created: int


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
            import logging
            logging.getLogger(__name__).warning(
                "Log shipping denied: IP %s not in allowlist for %s",
                client_ip,
                pattern.name
            )
            raise HTTPException(
                status_code=403,
                detail=f"IP {client_ip} not in allowlist for this index pattern",
            )

    return pattern


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
    # Validate the auth token first and get the index pattern for enrichment config
    # This also checks IP allowlist
    index_pattern = await validate_log_shipping_token(index_suffix, authorization, db, request)

    # Check rate limits if enabled
    if index_pattern.rate_limit_enabled:
        max_requests = index_pattern.rate_limit_requests_per_minute or 100
        max_events = index_pattern.rate_limit_events_per_minute or 50000
        check_rate_limit(str(index_pattern.id), len(logs), max_requests, max_events)

    if os_client is None:
        raise HTTPException(
            status_code=503,
            detail="OpenSearch not configured",
        )

    percolator_index = f"chad-percolator-{index_suffix}"
    alerts_index = f"chad-alerts-{index_suffix}"

    # Check percolator index exists
    if not os_client.indices.exists(index=percolator_index):
        raise HTTPException(404, f"No percolator index for {index_suffix}")

    alert_service = AlertService(os_client)
    total_matches = 0
    alerts_created = []

    # Health metrics tracking
    logs_errored = 0
    latencies = []
    processing_errors = []

    # Cache exceptions per rule to avoid repeated DB queries
    rule_exceptions_cache: dict[str, list[dict]] = {}

    for log in logs:
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

        # Run percolate query
        try:
            matches = alert_service.match_log(percolator_index, log)
        except Exception as e:
            processing_errors.append(f"Percolate failed for log: {str(e)}")
            logs_errored += 1
            # Continue to next log instead of failing entire batch
            continue

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
                                RuleException.is_active == True,
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

                # Enrich log with GeoIP data if configured
                enriched_log = await enrich_alert(db, log, index_pattern)

                # Create alert
                alert = alert_service.create_alert(
                    alerts_index=alerts_index,
                    rule_id=rule_id,
                    rule_title=match["rule_title"],
                    severity=match["severity"],
                    tags=match.get("tags", []),
                    log_document=enriched_log,
                )
                alerts_created.append(alert)
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
                        import logging
                        logger = logging.getLogger(__name__)

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
                                except (ValueError, yaml.YAMLError, Exception):
                                    pass

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
                                except (ValueError, yaml.YAMLError, Exception):
                                    pass

                            # Deduplicate tags while preserving order
                            seen = set()
                            unique_tags = []
                            for tag in correlation_tags:
                                if tag not in seen:
                                    seen.add(tag)
                                    unique_tags.append(tag)

                            correlation_alert = alert_service.create_alert(
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
                    import logging
                    logging.getLogger(__name__).error("Correlation check failed: %s", e)

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
                    import logging
                    logging.getLogger(__name__).warning("WebSocket broadcast failed: %s", e)

            except Exception as e:
                processing_errors.append(f"Alert creation failed for match: {str(e)}")
                logs_errored += 1
                continue
        # Send notifications through the new notification system
    if alerts_created:
        # Get app URL for alert links
        app_url = await get_app_url(db)

        # Send notifications for each alert
        for alert in alerts_created:
            alert_url = f"{app_url}/alerts/{alert['alert_id']}" if app_url else None
            try:
                await send_alert_notification(
                    db,
                    alert_id=UUID(alert["alert_id"]) if isinstance(alert["alert_id"], str) else alert["alert_id"],
                    rule_title=alert.get("rule_title", "Unknown Rule"),
                    severity=alert.get("severity", "medium"),
                    matched_log=alert.get("log_document", {}),
                    alert_url=alert_url,
                )
            except Exception as e:
                # Log but don't fail the request if notification fails
                import logging
                logging.getLogger(__name__).error("Failed to send notification: %s", e)

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
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "Batch processing had %d errors: First 3 errors: %s",
                len(processing_errors),
                processing_errors[:3]
            )

    except Exception as e:
        # Log but don't fail the request if metric recording fails
        import logging
        logging.getLogger(__name__).error("Failed to record health metrics: %s", e)

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

    if not os_client.indices.exists(index=percolator_index):
        raise HTTPException(404, f"No percolator index for {index_suffix}")

    alert_service = AlertService(os_client)
    matches = alert_service.match_log(percolator_index, log)

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
                    RuleException.is_active == True,
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
                from app.services.alerts import check_exception_match
                from app.models.rule_exception import ExceptionOperator
                if check_exception_match(log, exc["field"], ExceptionOperator(exc["operator"]), exc["value"]):
                    suppressed = True
                    matching_exception = exc
                    break
        except (ValueError, Exception):
            pass

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
