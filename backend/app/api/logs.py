"""
Log matching API - receives logs from Fluentd and matches against percolator rules.

Flow:
1. Fluentd sends logs: POST /api/logs/{index_suffix}
2. Backend validates auth token against index pattern
3. Backend runs percolate query against corresponding percolator index
4. For each match, create alert document
5. Store alerts in OpenSearch alerts index
6. Trigger webhook notifications (async)
"""

import secrets
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from opensearchpy import OpenSearch
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_opensearch_client_optional
from app.db.session import get_db
from app.models.health_metrics import IndexHealthMetrics
from app.models.index_pattern import IndexPattern
from app.models.rule_exception import RuleException
from app.services.alerts import AlertService, should_suppress_alert
from app.services.enrichment import enrich_alert
from app.services.notification import send_alert_notification
from app.services.settings import get_app_url
from app.services.correlation import check_correlation
from app.services.websocket import manager, AlertBroadcast

router = APIRouter(prefix="/logs", tags=["logs"])


class LogMatchResponse(BaseModel):
    logs_received: int
    matches_found: int
    alerts_created: int


async def validate_log_shipping_token(
    index_suffix: str,
    authorization: str | None,
    db: AsyncSession,
) -> IndexPattern:
    """
    Validate the auth token for log shipping endpoint.

    Args:
        index_suffix: The index suffix from the URL path
        authorization: The Authorization header value
        db: Database session

    Returns:
        The matching IndexPattern if valid

    Raises:
        HTTPException: If authentication fails
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

    return pattern


@router.post("/{index_suffix}", response_model=LogMatchResponse)
async def receive_logs(
    index_suffix: str,
    logs: list[dict[str, Any]],
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Receive logs from Fluentd and match against deployed rules.

    This endpoint requires a valid auth token associated with the index pattern.
    The token should be provided in the Authorization header: Bearer <token>

    Args:
        index_suffix: The index suffix (e.g., "my-logs" for chad-percolator-my-logs)
        logs: List of log documents
        authorization: Bearer token for authentication

    Returns:
        Summary of matches found
    """
    # Validate the auth token first and get the index pattern for enrichment config
    index_pattern = await validate_log_shipping_token(index_suffix, authorization, db)

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
                            correlation_alert = alert_service.create_alert(
                                alerts_index=alerts_index,
                                rule_id=corr["correlation_rule_id"],
                                rule_title=corr["correlation_name"],
                                severity=corr.get("severity", "high"),
                                tags=["correlation"],
                                log_document={
                                    "correlation": {
                                        "correlation_rule_id": corr["correlation_rule_id"],
                                        "correlation_name": corr["correlation_name"],
                                        "source_alerts": corr.get("source_alerts", []),
                                        "entity_field": corr.get("entity_field"),
                                        "entity_value": corr.get("entity_value"),
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
                                logger.error(f"WebSocket broadcast failed for correlation alert: {e}")

                            logger.info(
                                "Correlation alert created: %s (entity: %s)",
                                corr['correlation_name'],
                                corr.get('entity_value')
                            )
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).error(f"Correlation check failed: {e}")

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
                    logging.getLogger(__name__).warning(f"WebSocket broadcast failed: {e}")

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
                logging.getLogger(__name__).error(f"Failed to send notification: {e}")

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
            avg_latency_ms=avg_latency,
        )
        db.add(metric)
        await db.commit()

        # Log processing errors for monitoring
        if processing_errors:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"Batch processing had {len(processing_errors)} errors: "
                f"First 3 errors: {processing_errors[:3]}"
            )

    except Exception as e:
        # Log but don't fail the request if metric recording fails
        import logging
        logging.getLogger(__name__).error(f"Failed to record health metrics: {e}")

    return LogMatchResponse(
        logs_received=len(logs),
        matches_found=total_matches,
        alerts_created=len(alerts_created),
    )


@router.post("/{index_suffix}/test")
async def test_log_matching(
    index_suffix: str,
    log: dict[str, Any],
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
    # Validate the auth token first
    await validate_log_shipping_token(index_suffix, authorization, db)

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
