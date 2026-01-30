"""Alerts API - view and manage alerts."""

import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client, require_permission_dep
from app.core.errors import not_found
from app.db.session import get_db
from app.models.alert_comment import AlertComment
from app.models.user import User
from app.schemas.alert import (
    AlertCluster,
    AlertCountsResponse,
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdate,
    ClusteredAlertListResponse,
)
from app.schemas.alert_comment import AlertCommentCreate, AlertCommentResponse, AlertCommentUpdate
from app.services.alerts import AlertService, cluster_alerts
from app.services.audit import audit_log
from app.services.settings import get_setting
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

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


@router.get("", response_model=AlertListResponse | ClusteredAlertListResponse)
async def list_alerts(
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    owner: str | None = Query(None, description="Filter by owner (use 'me' for current user)"),
    index_pattern: str = Query("chad-alerts-*", description="Alerts index pattern"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    cluster: bool = Query(True, description="Apply alert clustering when enabled globally"),
):
    """List alerts with optional filters and clustering."""
    owner_id = None
    if owner == "me":
        owner_id = str(current_user.id)
    elif owner:
        owner_id = owner

    alert_service = AlertService(os_client)

    # Check if clustering is enabled first to determine fetch strategy
    clustering_settings = None
    if cluster:
        clustering_settings = await get_setting(db, "alert_clustering")

    # Determine fetch strategy based on filters
    # When clustering is enabled or filtering by owner, fetch more alerts
    # (pagination doesn't make sense with these filters - we need to see the full picture)
    fetch_limit = limit
    fetch_offset = offset
    if clustering_settings and clustering_settings.get("enabled", False):
        fetch_limit = 1000  # Fetch more alerts when clustering
        fetch_offset = 0    # Always start from the beginning for clustering
    elif owner_id:
        # "Assigned to me" filter - fetch all assigned alerts for the user
        # Users typically want to see all their assigned alerts at once
        fetch_limit = 1000
        fetch_offset = 0

    result = alert_service.get_alerts(
        index_pattern=index_pattern,
        status=status,
        severity=severity,
        rule_id=rule_id,
        owner_id=owner_id,
        limit=fetch_limit,
        offset=fetch_offset,
    )

    # Apply clustering if enabled
    if clustering_settings and clustering_settings.get("enabled", False):
        # Apply clustering to the results
        clusters = cluster_alerts(result["alerts"], clustering_settings)

        # Convert clusters to response format
        cluster_responses = []
        for c in clusters:
            cluster_responses.append(
                AlertCluster(
                    representative=AlertResponse(**c["representative"]),
                    count=c["count"],
                    alert_ids=c["alert_ids"],
                    alerts=[AlertResponse(**a) for a in c["alerts"]],
                    time_range=c["time_range"],
                )
            )

        return ClusteredAlertListResponse(
            total=result["total"],
            total_clusters=len(cluster_responses),
            clusters=cluster_responses,
        )

    # Return non-clustered response
    return result


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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Update status for multiple alerts."""
    from sqlalchemy import select

    from app.models.alert import Alert

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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Delete multiple alerts."""
    from sqlalchemy import delete as sql_delete
    from sqlalchemy import select

    from app.models.alert import Alert

    success = []
    failed = []

    # Convert string IDs to UUIDs and strings for comparison
    alert_ids = [UUID(aid) for aid in data.alert_ids]
    alert_id_strs = [str(aid) for aid in data.alert_ids]

    # Query database by alert_id (OpenSearch document ID), not database id
    result = await db.execute(select(Alert).where(Alert.alert_id.in_(alert_id_strs)))
    alerts = {alert.alert_id: alert for alert in result.scalars().all()}

    for alert_id_uuid, alert_id_str in zip(alert_ids, alert_id_strs):
        try:
            # Check if alert exists in database
            if alert_id_str in alerts:
                alert = alerts[alert_id_str]

                # Delete from OpenSearch first (fail fast)
                # Use refresh=True to ensure immediate consistency for subsequent queries
                try:
                    os_client.delete(index=alert.alert_index, id=alert.alert_id, refresh=True)
                except Exception as e:
                    # Don't proceed with DB deletion if OpenSearch fails
                    failed.append({"id": alert_id_str, "error": f"Failed to delete from OpenSearch: {e}"})
                    continue

                # Delete from database
                await db.execute(sql_delete(Alert).where(Alert.alert_id == alert_id_str))

                await audit_log(db, current_user.id, "alert.bulk_delete", "alert", alert_id_str,
                              {"title": alert.title}, ip_address=get_client_ip(request))
                success.append(alert_id_str)
            else:
                # Alert not in database, try to delete from OpenSearch only
                try:
                    # Search for the alert in OpenSearch
                    search_result = os_client.search(
                        index="chad-alerts-*",
                        body={"query": {"term": {"alert_id": alert_id_str}}}
                    )
                    hits = search_result.get("hits", {}).get("hits", [])

                    if not hits:
                        failed.append({"id": alert_id_str, "error": "Not found"})
                        continue

                    # Delete from OpenSearch
                    # Use refresh=True to ensure immediate consistency for subsequent queries
                    hit = hits[0]
                    os_client.delete(index=hit["_index"], id=hit["_id"], refresh=True)

                    await audit_log(db, current_user.id, "alert.bulk_delete", "alert", alert_id_str,
                                  {"note": "Alert deleted from OpenSearch only (no DB record)"},
                                  ip_address=get_client_ip(request))
                    success.append(alert_id_str)
                except Exception as e:
                    logger.warning(f"Failed to delete alert {alert_id_str}: {e}")
                    failed.append({"id": alert_id_str, "error": "Failed to delete alert"})
        except Exception as e:
            logger.warning(f"Failed to delete alert {alert_id_str}: {e}")
            failed.append({"id": alert_id_str, "error": "Failed to delete alert"})

    await db.commit()

    return {"success": success, "failed": failed}


# ----- Alert Comments Endpoints -----


@router.get("/{alert_id}/comments", response_model=list[AlertCommentResponse])
async def list_alert_comments(
    alert_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List comments for an alert."""
    result = await db.execute(
        select(AlertComment)
        .where(AlertComment.alert_id == alert_id, AlertComment.deleted_at.is_(None))
        .order_by(AlertComment.created_at.asc())
    )
    comments = result.scalars().all()
    return [
        AlertCommentResponse(
            id=c.id,
            alert_id=c.alert_id,
            user_id=c.user_id,
            username=c.user.email if c.user else "Unknown",
            content=c.content,
            created_at=c.created_at,
            updated_at=c.updated_at,
            is_deleted=c.deleted_at is not None,
        )
        for c in comments
    ]


@router.post("/{alert_id}/comments", response_model=AlertCommentResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_comment(
    alert_id: str,
    comment_data: AlertCommentCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Add a comment to an alert. Requires manage_alerts permission (viewers cannot comment)."""
    comment = AlertComment(
        alert_id=alert_id,
        user_id=current_user.id,
        content=comment_data.content,
    )
    db.add(comment)
    await audit_log(
        db, current_user.id, "alert.comment_add", "alert_comment",
        str(comment.id), {"alert_id": alert_id}, ip_address=get_client_ip(request)
    )
    await db.commit()
    await db.refresh(comment)

    return AlertCommentResponse(
        id=comment.id,
        alert_id=comment.alert_id,
        user_id=comment.user_id,
        username=current_user.email,
        content=comment.content,
        created_at=comment.created_at,
        is_deleted=False,
    )


@router.patch("/{alert_id}/comments/{comment_id}", response_model=AlertCommentResponse)
async def update_alert_comment(
    alert_id: str,
    comment_id: UUID,
    comment_data: AlertCommentUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Update own comment. Users can only edit their own comments."""
    result = await db.execute(
        select(AlertComment).where(
            AlertComment.id == comment_id,
            AlertComment.alert_id == alert_id,
            AlertComment.deleted_at.is_(None),
        )
    )
    comment = result.scalar_one_or_none()

    if not comment:
        raise not_found("Comment")

    # Only allow editing own comments
    if comment.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only edit your own comments"
        )

    comment.content = comment_data.content
    comment.updated_at = datetime.now(UTC)
    await audit_log(
        db, current_user.id, "alert.comment_edit", "alert_comment",
        str(comment_id), {"alert_id": alert_id}, ip_address=get_client_ip(request)
    )
    await db.commit()
    await db.refresh(comment)

    return AlertCommentResponse(
        id=comment.id,
        alert_id=comment.alert_id,
        user_id=comment.user_id,
        username=current_user.email,
        content=comment.content,
        created_at=comment.created_at,
        updated_at=comment.updated_at,
        is_deleted=False,
    )


@router.delete("/{alert_id}/comments/{comment_id}")
async def delete_alert_comment(
    alert_id: str,
    comment_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("admin"))],
):
    """Soft delete a comment (admin only)."""
    result = await db.execute(
        select(AlertComment).where(
            AlertComment.id == comment_id,
            AlertComment.alert_id == alert_id,
        )
    )
    comment = result.scalar_one_or_none()

    if not comment:
        raise not_found("Comment")

    comment.deleted_at = datetime.now(UTC)
    comment.deleted_by_id = current_user.id
    await audit_log(
        db, current_user.id, "alert.comment_delete", "alert_comment",
        str(comment_id), {"alert_id": alert_id}, ip_address=get_client_ip(request)
    )
    await db.commit()

    return {"message": "Comment deleted"}


# ----- Alert Ownership Endpoints -----


@router.post("/{alert_id}/assign")
async def assign_alert(
    alert_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Assign alert to current user. Requires manage_alerts permission (viewers cannot take ownership)."""
    try:
        # First find the alert to get its index and document ID
        result = os_client.search(
            index="chad-alerts-*",
            body={"query": {"term": {"alert_id": alert_id}}},
        )
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            raise not_found("Alert", details={"alert_id": alert_id})

        hit = hits[0]
        alert_index = hit["_index"]
        doc_id = hit["_id"]

        os_client.update(
            index=alert_index,
            id=doc_id,
            body={
                "doc": {
                    "owner_id": str(current_user.id),
                    "owner_username": current_user.email,
                    "owned_at": datetime.now(UTC).isoformat(),
                }
            },
            refresh=True,
        )
        await audit_log(
            db, current_user.id, "alert.assign", "alert",
            alert_id, {"owner": current_user.email}, ip_address=get_client_ip(request)
        )
        await db.commit()
        return {"message": "Alert assigned", "owner": current_user.email}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/unassign")
async def unassign_alert(
    alert_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Release ownership of alert. Requires manage_alerts permission."""
    try:
        # First find the alert to get its index and document ID
        result = os_client.search(
            index="chad-alerts-*",
            body={"query": {"term": {"alert_id": alert_id}}},
        )
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            raise not_found("Alert", details={"alert_id": alert_id})

        hit = hits[0]
        alert_index = hit["_index"]
        doc_id = hit["_id"]

        os_client.update(
            index=alert_index,
            id=doc_id,
            body={
                "doc": {
                    "owner_id": None,
                    "owner_username": None,
                    "owned_at": None,
                }
            },
            refresh=True,
        )
        await audit_log(
            db, current_user.id, "alert.unassign", "alert",
            alert_id, {}, ip_address=get_client_ip(request)
        )
        await db.commit()
        return {"message": "Alert unassigned"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
