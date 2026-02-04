"""Dashboard statistics API."""

import logging
from datetime import datetime
from typing import Annotated

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_opensearch_client_optional
from app.models.rule import Rule
from app.models.user import User

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/dashboard")
async def get_dashboard_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """
    Get dashboard statistics.

    Returns:
    - Rule counts by status
    - Alert counts by severity and status
    - Recent alerts
    """
    # Rule statistics from PostgreSQL
    rule_stats = await _get_rule_stats(db)

    # Alert statistics from OpenSearch (if configured)
    alert_stats = {"total": 0, "by_status": {}, "by_severity": {}, "today": 0}
    recent_alerts: list = []

    if os_client:
        alert_stats = _get_alert_stats(os_client)
        recent_alerts = _get_recent_alerts(os_client, limit=10)

    return {
        "rules": rule_stats,
        "alerts": alert_stats,
        "recent_alerts": recent_alerts,
        "generated_at": datetime.utcnow().isoformat(),
    }


async def _get_rule_stats(db: AsyncSession) -> dict:
    """Get rule statistics from PostgreSQL."""
    # Total rules
    total_result = await db.execute(select(func.count(Rule.id)))
    total = total_result.scalar() or 0

    # By status
    status_result = await db.execute(
        select(Rule.status, func.count(Rule.id)).group_by(Rule.status)
    )
    by_status = {str(row[0].value): row[1] for row in status_result.fetchall()}

    # Deployed count
    deployed_result = await db.execute(
        select(func.count(Rule.id)).where(Rule.deployed_at.isnot(None))
    )
    deployed = deployed_result.scalar() or 0

    return {
        "total": total,
        "by_status": by_status,
        "deployed": deployed,
    }


def _get_alert_stats(os_client: OpenSearch) -> dict:
    """Get alert statistics from OpenSearch."""
    try:
        # Count by status and severity
        status_agg = os_client.search(
            index="chad-alerts-*",
            body={
                "size": 0,
                "aggs": {
                    "by_status": {"terms": {"field": "status"}},
                    "by_severity": {"terms": {"field": "severity"}},
                },
            },
        )

        by_status = {
            b["key"]: b["doc_count"]
            for b in status_agg["aggregations"]["by_status"]["buckets"]
        }
        by_severity = {
            b["key"]: b["doc_count"]
            for b in status_agg["aggregations"]["by_severity"]["buckets"]
        }

        total = status_agg["hits"]["total"]["value"]

        # Today's alerts
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_result = os_client.count(
            index="chad-alerts-*",
            body={"query": {"range": {"created_at": {"gte": today.isoformat()}}}},
        )
        today_count = today_result["count"]

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "today": today_count,
        }
    except Exception:
        return {
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "today": 0,
        }


def _get_recent_alerts(os_client: OpenSearch, limit: int = 10) -> list:
    """Get most recent alerts."""
    try:
        result = os_client.search(
            index="chad-alerts-*",
            body={
                "size": limit,
                "sort": [{"created_at": {"order": "desc"}}],
                "_source": [
                    "alert_id",
                    "rule_title",
                    "severity",
                    "status",
                    "created_at",
                ],
            },
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception:
        return []


@router.get("/health")
async def get_system_health(
    _: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """
    Get system health status.

    Returns:
    - OpenSearch cluster health
    - Percolator index status
    - Alert index status
    """
    if not os_client:
        return {
            "status": "degraded",
            "error": "OpenSearch not configured",
        }

    try:
        # Cluster health
        cluster_health = os_client.cluster.health()

        # Get OpenSearch version info
        try:
            info = os_client.info()
            version = info.get("version", {}).get("number", "unknown")
        except Exception:
            version = "unknown"

        # Percolator indices
        try:
            percolator_indices = os_client.cat.indices(
                index="chad-percolator-*", format="json"
            )
        except Exception:
            percolator_indices = []

        # Alert indices
        try:
            alert_indices = os_client.cat.indices(
                index="chad-alerts-*", format="json"
            )
        except Exception:
            alert_indices = []

        return {
            "status": "healthy",
            "opensearch": {
                "status": cluster_health["status"],
                "cluster_name": cluster_health["cluster_name"],
                "number_of_nodes": cluster_health["number_of_nodes"],
                "version": version,
            },
            "percolator_indices": len(percolator_indices),
            "alert_indices": len(alert_indices),
        }
    except Exception as e:
        # Log the actual error for debugging, but don't expose details to user
        logger.error("OpenSearch health check failed: %s", e)
        return {
            "status": "unhealthy",
            "error": "Failed to connect to OpenSearch",
        }
