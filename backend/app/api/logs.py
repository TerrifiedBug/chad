"""
Log matching API - receives logs from Fluentd and matches against percolator rules.

Flow:
1. Fluentd sends logs: POST /api/logs/{index_suffix}
2. Backend runs percolate query against corresponding percolator index
3. For each match, create alert document
4. Store alerts in OpenSearch alerts index
5. Trigger webhook notifications (async)
"""

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from opensearchpy import OpenSearch
from pydantic import BaseModel

from app.api.deps import get_opensearch_client_optional
from app.services.alerts import AlertService

router = APIRouter(prefix="/logs", tags=["logs"])


class LogMatchResponse(BaseModel):
    logs_received: int
    matches_found: int
    alerts_created: int


@router.post("/{index_suffix}", response_model=LogMatchResponse)
async def receive_logs(
    index_suffix: str,
    logs: list[dict[str, Any]],
    background_tasks: BackgroundTasks,
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Receive logs from Fluentd and match against deployed rules.

    This endpoint does NOT require authentication - it's called by Fluentd.
    Security should be handled at the network level (firewall, API gateway).

    Args:
        index_suffix: The index suffix (e.g., "vector-auditbeat" for chad-percolator-vector-auditbeat)
        logs: List of log documents

    Returns:
        Summary of matches found
    """
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
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Test a single log against deployed rules without creating alerts.

    Useful for testing rules during development.
    """
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
