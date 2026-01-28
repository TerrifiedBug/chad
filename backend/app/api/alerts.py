"""Alerts API - view and manage alerts."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client, require_permission_dep
from app.core.errors import not_found
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


# Bulk operation schemas
MAX_BULK_OPERATIONS = 100


class BulkAlertStatusUpdate(BaseModel):
    alert_ids: list[str] = Field(..., min_length=1, max_length=MAX_BULK_OPERATIONS, description="List of alert IDs to update")
    status: str  # new, acknowledged, resolved, false_positive

    @field_validator('alert_ids')
    @classmethod
    def validate_alert_ids(cls, v):
        """Validate all IDs are valid UUIDs."""
        for alert_id in v:
            try:
                UUID(alert_id)
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid UUID format: {alert_id}")
        return v


class BulkAlertDelete(BaseModel):
    alert_ids: list[str] = Field(..., min_length=1, max_length=MAX_BULK_OPERATIONS, description="List of alert IDs to delete")

    @field_validator('alert_ids')
    @classmethod
    def validate_alert_ids(cls, v):
        """Validate all IDs are valid UUIDs."""
        for alert_id in v:
            try:
                UUID(alert_id)
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid UUID format: {alert_id}")
        return v


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
        raise not_found("Alert", details={"alert_id": alert_id})

    return alert


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    request: Request,
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    index_pattern: str = Query("chad-alerts-*"),
):
    """Update alert status (acknowledge, resolve, mark as false positive)."""
    alert_service = AlertService(os_client)

    # First find the alert to get its index
    alert = alert_service.get_alert(index_pattern, alert_id)
    if alert is None:
        raise not_found("Alert", details={"alert_id": alert_id})

    # Find the actual index the alert is in
    result = os_client.search(
        index=index_pattern,
        body={"query": {"term": {"alert_id": alert_id}}},
    )
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        raise not_found("Alert", details={"alert_id": alert_id})

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


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Delete an alert."""
    alert_service = AlertService(os_client)
    success = await alert_service.delete_alert(
        db=db,
        alert_id=alert_id,
        current_user_id=current_user.id,
        ip_address=get_client_ip(request)
    )

    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")


@router.post("/bulk/status", response_model=dict)
async def bulk_update_alert_status(
    data: BulkAlertStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update status for multiple alerts."""
    from app.models.alert import Alert
    from sqlalchemy import select

    success = []
    failed = []

    # Convert string IDs to UUIDs
    alert_ids = [UUID(aid) for aid in data.alert_ids]

    # Single query with IN clause to avoid N+1
    result = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
    alerts = {alert.id: alert for alert in result.scalars().all()}

    for alert_id in alert_ids:
        if alert_id in alerts:
            try:
                alert = alerts[alert_id]
                old_status = alert.status
                alert.status = data.status

                await audit_log(db, current_user.id, "alert.bulk_status_update", "alert", str(alert_id),
                              {"old_status": old_status, "new_status": alert.status},
                              ip_address=get_client_ip(request))
                success.append(str(alert_id))
            except Exception as e:
                failed.append({"id": str(alert_id), "error": str(e)})
        else:
            failed.append({"id": str(alert_id), "error": "Not found"})

    await db.commit()

    return {"success": success, "failed": failed}


@router.post("/bulk/delete", response_model=dict)
async def bulk_delete_alerts(
    data: BulkAlertDelete,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Delete multiple alerts."""
    from app.models.alert import Alert
    from sqlalchemy import select, delete as sql_delete

    success = []
    failed = []

    # Convert string IDs to UUIDs
    alert_ids = [UUID(aid) for aid in data.alert_ids]

    # Single query with IN clause to avoid N+1
    result = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
    alerts = {alert.id: alert for alert in result.scalars().all()}

    for alert_id in alert_ids:
        if alert_id in alerts:
            try:
                alert = alerts[alert_id]

                # Delete from OpenSearch first (fail fast)
                try:
                    os_client.delete(index=alert.alert_index, id=alert.alert_id)
                except Exception as e:
                    # Don't proceed with DB deletion if OpenSearch fails
                    failed.append({"id": str(alert_id), "error": f"Failed to delete from OpenSearch: {e}"})
                    continue

                # Delete from database
                await db.execute(sql_delete(Alert).where(Alert.id == alert_id))

                await audit_log(db, current_user.id, "alert.bulk_delete", "alert", str(alert_id),
                              {"title": alert.title}, ip_address=get_client_ip(request))
                success.append(str(alert_id))
            except Exception as e:
                failed.append({"id": str(alert_id), "error": str(e)})
        else:
            failed.append({"id": str(alert_id), "error": "Not found"})

    await db.commit()

    return {"success": success, "failed": failed}
