"""Alerts API - view and manage alerts."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from opensearchpy import OpenSearch
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client
from app.db.session import get_db
from app.utils.request import get_client_ip
from app.models.user import User
from app.services.audit import audit_log
from app.schemas.alert import (
    AlertCountsResponse,
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdate,
)
from app.services.alerts import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    index_pattern: str = Query("chad-alerts-*", description="Alerts index pattern"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List alerts with optional filters."""
    alert_service = AlertService(os_client)
    return alert_service.get_alerts(
        index_pattern=index_pattern,
        status=status,
        severity=severity,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )


@router.get("/counts", response_model=AlertCountsResponse)
async def get_alert_counts(
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
    index_pattern: str = Query("chad-alerts-*", description="Alerts index pattern"),
):
    """Get alert counts by status and severity for dashboard."""
    alert_service = AlertService(os_client)
    return alert_service.get_alert_counts(index_pattern=index_pattern)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    _: Annotated[User, Depends(get_current_user)],
    index_pattern: str = Query("chad-alerts-*"),
):
    """Get a single alert by ID."""
    alert_service = AlertService(os_client)
    alert = alert_service.get_alert(index_pattern, alert_id)

    if alert is None:
        raise HTTPException(404, "Alert not found")

    return alert


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    request: Request,
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    index_pattern: str = Query("chad-alerts-*"),
):
    """Update alert status (acknowledge, resolve, mark as false positive)."""
    alert_service = AlertService(os_client)

    # First find the alert to get its index
    alert = alert_service.get_alert(index_pattern, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")

    # Find the actual index the alert is in
    result = os_client.search(
        index=index_pattern,
        body={"query": {"term": {"alert_id": alert_id}}},
    )
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        raise HTTPException(404, "Alert not found")

    alert_index = hits[0]["_index"]

    success = alert_service.update_alert_status(
        alerts_index=alert_index,
        alert_id=alert_id,
        status=update.status,
        user_id=current_user.email,  # Store email for display
    )

    if not success:
        raise HTTPException(500, "Failed to update alert status")

    await audit_log(db, current_user.id, "alert.status_update", "alert", alert_id, {"status": update.status}, ip_address=get_client_ip(request))
    await db.commit()

    return {"success": True, "status": update.status}
