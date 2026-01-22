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
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from opensearchpy import OpenSearch
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_opensearch_client_optional
from app.db.session import get_db
from app.models.index_pattern import IndexPattern
from app.services.alerts import AlertService

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
    # Validate the auth token first
    await validate_log_shipping_token(index_suffix, authorization, db)

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

    for log in logs:
        # Run percolate query
        matches = alert_service.match_log(percolator_index, log)

        for match in matches:
            # Only process enabled rules
            if not match.get("enabled", True):
                continue

            # Create alert
            alert = alert_service.create_alert(
                alerts_index=alerts_index,
                rule_id=match["rule_id"],
                rule_title=match["rule_title"],
                severity=match["severity"],
                tags=match.get("tags", []),
                log_document=log,
            )
            alerts_created.append(alert)
            total_matches += 1

    # Send webhook notifications in background
    if alerts_created:
        from app.services.webhooks import WebhookService
        background_tasks.add_task(
            WebhookService.send_notifications,
            os_client,
            alerts_created,
        )

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

    return {
        "matches": [
            {
                "rule_id": m["rule_id"],
                "rule_title": m["rule_title"],
                "severity": m["severity"],
                "tags": m.get("tags", []),
                "enabled": m.get("enabled", True),
            }
            for m in matches
        ]
    }
