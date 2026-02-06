"""Alerts API - view and manage alerts."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client, require_permission_dep
from app.core.circuit_breaker import CircuitBreakerError, get_circuit_breaker
from app.core.errors import not_found
from app.core.exceptions import OpenSearchUnavailableError
from app.core.redis import get_redis
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
    RelatedAlertsResponse,
)
from app.schemas.alert_comment import AlertCommentCreate, AlertCommentResponse, AlertCommentUpdate
from app.services.alert_cache import AlertCache
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
    change_reason: str | None = Field(None, min_length=1, max_length=10000)

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
    change_reason: str | None = Field(None, min_length=1, max_length=10000)

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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    owner: str | None = Query(None, description="Filter by owner (use 'me' for current user)"),
    index_pattern: str = Query("chad-alerts-*", description="Alerts index pattern"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    cluster: bool = Query(True, description="Apply alert clustering when enabled globally"),
    exclude_ioc: bool = Query(False, description="Exclude IOC detection alerts"),
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

    # Use cached query path with circuit breaker protection
    try:
        redis = await get_redis()
        cache = AlertCache(redis, ttl=30)
    except Exception:
        cache = None

    cb = get_circuit_breaker("opensearch_alerts", failure_threshold=3, recovery_timeout=30.0)

    try:
        if cache:
            result = await cb.call(
                alert_service.get_alerts_cached,
                cache=cache,
                index_pattern=index_pattern,
                status=status,
                severity=severity,
                rule_id=rule_id,
                owner_id=owner_id,
                limit=fetch_limit,
                offset=fetch_offset,
                exclude_ioc=exclude_ioc,
            )
        else:
            # No Redis available - call OpenSearch directly through circuit breaker
            result = await cb.call(
                alert_service.get_alerts,
                index_pattern=index_pattern,
                status=status,
                severity=severity,
                rule_id=rule_id,
                owner_id=owner_id,
                limit=fetch_limit,
                offset=fetch_offset,
                exclude_ioc=exclude_ioc,
            )
            result["cached"] = False
            result["opensearch_available"] = True
    except (CircuitBreakerError, OpenSearchUnavailableError):
        raise HTTPException(status_code=503, detail={
            "message": "OpenSearch is currently unavailable",
            "opensearch_available": False,
            "cached": False,
        })

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
    exclude_ioc: bool = Query(False, description="Exclude IOC detection alerts from counts"),
):
    """Get alert counts by status and severity for dashboard."""
    alert_service = AlertService(os_client)
    return alert_service.get_alert_counts(index_pattern=index_pattern, exclude_ioc=exclude_ioc)


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


@router.get("/{alert_id}/related", response_model=RelatedAlertsResponse)
async def get_related_alerts(
    alert_id: str,
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    index_pattern: str = Query("chad-alerts-*"),
    limit: int = Query(50, ge=1, le=100, description="Max related alerts to return"),
):
    """
    Get alerts related to this one (same rule, within clustering time window).

    Returns empty list if alert clustering is disabled.
    """
    # Check if clustering is enabled
    clustering_settings = await get_setting(db, "alert_clustering")
    if not clustering_settings or not clustering_settings.get("enabled", False):
        return RelatedAlertsResponse(
            alert_id=alert_id,
            related_count=0,
            clustering_enabled=False,
            window_minutes=None,
            alerts=[],
        )

    window_minutes = clustering_settings.get("window_minutes", 60)

    # Get the current alert
    alert_service = AlertService(os_client)
    alert = alert_service.get_alert(index_pattern, alert_id)

    if alert is None:
        raise not_found("Alert", details={"alert_id": alert_id})

    rule_id = alert.get("rule_id")
    alert_timestamp = alert.get("created_at")

    if not rule_id or not alert_timestamp:
        return RelatedAlertsResponse(
            alert_id=alert_id,
            related_count=0,
            clustering_enabled=True,
            window_minutes=window_minutes,
            alerts=[],
        )

    # Parse timestamp and calculate time range
    if isinstance(alert_timestamp, str):
        alert_time = datetime.fromisoformat(alert_timestamp.replace("Z", "+00:00"))
    else:
        alert_time = alert_timestamp

    # Query for related alerts: same rule_id, within ±window_minutes, excluding this alert
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"rule_id": rule_id}},
                    {
                        "range": {
                            "created_at": {
                                "gte": f"now-{window_minutes}m",
                                "lte": f"now+{window_minutes}m",
                            }
                        }
                    },
                ],
                "must_not": [
                    {"term": {"alert_id": alert_id}}
                ],
            }
        },
        "sort": [{"created_at": {"order": "desc"}}],
        "size": limit,
    }

    # Use time-anchored range relative to the alert's timestamp
    query["query"]["bool"]["must"][1] = {
        "range": {
            "created_at": {
                "gte": (alert_time - timedelta(minutes=window_minutes)).isoformat(),
                "lte": (alert_time + timedelta(minutes=window_minutes)).isoformat(),
            }
        }
    }

    try:
        result = os_client.search(index=index_pattern, body=query)
        hits = result.get("hits", {}).get("hits", [])
        total = result.get("hits", {}).get("total", {}).get("value", 0)

        related_alerts = [AlertResponse(**hit["_source"]) for hit in hits]

        return RelatedAlertsResponse(
            alert_id=alert_id,
            related_count=total,
            clustering_enabled=True,
            window_minutes=window_minutes,
            alerts=related_alerts,
        )
    except Exception as e:
        logger.warning("Failed to get related alerts: %s", e)
        return RelatedAlertsResponse(
            alert_id=alert_id,
            related_count=0,
            clustering_enabled=True,
            window_minutes=window_minutes,
            alerts=[],
        )


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
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

    # Invalidate alert cache after status change
    try:
        redis = await get_redis()
        cache = AlertCache(redis)
        await cache.invalidate()
    except Exception:
        pass  # Cache invalidation failure is non-critical

    return {"success": True, "status": update.status}


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
    change_reason: str | None = None,
):
    """Delete an alert."""
    alert_service = AlertService(os_client)
    success = await alert_service.delete_alert(
        db=db,
        alert_id=alert_id,
        current_user_id=current_user.id,
        ip_address=get_client_ip(request),
        change_reason=change_reason,
    )

    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Invalidate alert cache after deletion
    try:
        redis = await get_redis()
        cache = AlertCache(redis)
        await cache.invalidate()
    except Exception:
        pass  # Cache invalidation failure is non-critical


@router.post("/bulk/status", response_model=dict)
async def bulk_update_alert_status(
    data: BulkAlertStatusUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Update status for multiple alerts."""
    alert_service = AlertService(os_client)
    success = []
    failed = []

    for alert_id_str in data.alert_ids:
        try:
            # Find alert in OpenSearch to get its index
            search_result = os_client.search(
                index="chad-alerts-*",
                body={"query": {"term": {"alert_id": alert_id_str}}},
            )
            hits = search_result.get("hits", {}).get("hits", [])
            if not hits:
                failed.append({"id": alert_id_str, "error": "Not found"})
                continue

            alert_index = hits[0]["_index"]
            old_status = hits[0]["_source"].get("status", "unknown")

            # Update in OpenSearch
            updated = alert_service.update_alert_status(
                alerts_index=alert_index,
                alert_id=alert_id_str,
                status=data.status,
                user_id=current_user.email,
            )
            if not updated:
                failed.append({"id": alert_id_str, "error": "OpenSearch update failed"})
                continue

            details: dict = {"old_status": old_status, "new_status": data.status}
            if data.change_reason:
                details["change_reason"] = data.change_reason
            await audit_log(
                db, current_user.id, "alert.bulk_status_update",
                "alert", alert_id_str, details,
                ip_address=get_client_ip(request),
            )
            success.append(alert_id_str)
        except Exception as e:
            logger.warning("Failed to update alert %s: %s", alert_id_str, type(e).__name__)
            failed.append({"id": alert_id_str, "error": "Update failed"})

    await db.commit()

    # Invalidate alert cache after bulk status change
    try:
        redis = await get_redis()
        cache = AlertCache(redis)
        await cache.invalidate()
    except Exception:
        pass  # Cache invalidation failure is non-critical

    return {"success": success, "failed": failed}


@router.post("/bulk/delete", response_model=dict)
async def bulk_delete_alerts(
    data: BulkAlertDelete,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
):
    """Delete multiple alerts from OpenSearch."""
    success = []
    failed = []

    # Validate alert IDs are hex strings to prevent injection
    alert_id_strs = []
    for aid in data.alert_ids:
        if not all(c in '0123456789abcdefABCDEF-' for c in aid):
            failed.append({"id": aid, "error": "Invalid alert ID format"})
            continue
        alert_id_strs.append(aid)

    for alert_id_str in alert_id_strs:
        try:
            search_result = os_client.search(
                index="chad-alerts-*",
                body={"query": {"term": {"alert_id": alert_id_str}}},
            )
            hits = search_result.get("hits", {}).get("hits", [])

            if not hits:
                failed.append({"id": alert_id_str, "error": "Not found"})
                continue

            hit = hits[0]
            os_client.delete(index=hit["_index"], id=hit["_id"], refresh=True)

            source = hit["_source"]
            title = source.get("title", source.get("rule_title", "Unknown"))
            delete_details: dict = {"title": title}
            if data.change_reason:
                delete_details["change_reason"] = data.change_reason
            await audit_log(
                db, current_user.id, "alert.bulk_delete", "alert",
                alert_id_str, delete_details,
                ip_address=get_client_ip(request),
            )
            success.append(alert_id_str)
        except Exception as e:
            logger.warning("Failed to delete alert %s: %s", alert_id_str, e)
            failed.append({"id": alert_id_str, "error": "Failed to delete alert"})

    await db.commit()

    # Invalidate alert cache after bulk deletion
    try:
        redis = await get_redis()
        cache = AlertCache(redis)
        await cache.invalidate()
    except Exception:
        pass  # Cache invalidation failure is non-critical

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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
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
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
    os_client: Annotated[OpenSearch, Depends(get_opensearch_client)],
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
