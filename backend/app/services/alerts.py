"""
Alert service - handles alert creation, storage, and retrieval.

Alerts are stored in OpenSearch with the following structure:
- chad-alerts-{index_suffix}: Index per log source
- Each alert contains: rule info, matched log, timestamp, status
"""

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dateutil import parser as date_parser
from opensearchpy import OpenSearch
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.rule_exception import ExceptionOperator
from app.services.system_log import LogCategory, system_log_service

if TYPE_CHECKING:
    from app.services.alert_cache import AlertCache

logger = logging.getLogger(__name__)


def generate_deterministic_alert_id(rule_id: str, log_document: dict) -> str:
    """
    Generate deterministic alert ID from rule + event.

    This ensures:
    - Same event + same rule + same minute = same alert ID
    - Retries overwrite instead of creating duplicates
    """
    # Create a hash of the log document content
    # Remove any fields that might change on retry (like processing timestamps)
    doc_copy = {k: v for k, v in log_document.items() if k not in ("ti_enrichment",)}
    event_hash = hashlib.sha256(
        json.dumps(doc_copy, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    # Time bucket (1 minute granularity) to allow the same event
    # within a minute window to be deduplicated
    time_bucket = datetime.now(UTC).strftime("%Y%m%d%H%M")

    # Combine rule_id + event_hash + time_bucket
    composite = f"{rule_id}:{event_hash}:{time_bucket}"
    return hashlib.sha256(composite.encode()).hexdigest()[:32]


def get_nested_value(obj: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation."""
    keys = path.split(".")
    value = obj
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def check_exception_match(
    log: dict,
    field: str,
    operator: ExceptionOperator,
    value: str,
) -> bool:
    """Check if a log document matches an exception condition."""
    log_value = get_nested_value(log, field)

    if log_value is None:
        return False

    log_value_str = str(log_value)

    if operator == ExceptionOperator.EQUALS:
        return log_value_str == value
    elif operator == ExceptionOperator.NOT_EQUALS:
        return log_value_str != value
    elif operator == ExceptionOperator.CONTAINS:
        return value in log_value_str
    elif operator == ExceptionOperator.NOT_CONTAINS:
        return value not in log_value_str
    elif operator == ExceptionOperator.STARTS_WITH:
        return log_value_str.startswith(value)
    elif operator == ExceptionOperator.ENDS_WITH:
        return log_value_str.endswith(value)
    elif operator == ExceptionOperator.REGEX:
        try:
            return bool(re.search(value, log_value_str))
        except re.error:
            return False
    elif operator == ExceptionOperator.IN_LIST:
        try:
            value_list = json.loads(value)
            return log_value_str in value_list
        except json.JSONDecodeError:
            return False

    return False


def should_suppress_alert(
    log: dict,
    exceptions: list[dict],
) -> bool:
    """Check if an alert should be suppressed based on active exceptions.

    Exceptions are grouped by group_id:
    - Exceptions within the same group are ANDed (all must match)
    - Different groups are ORed (if any group fully matches, suppress)

    This allows complex exception rules like:
    "Suppress when (user.name = 'admin' AND host.name = 'prod-01')"
    """
    # Group exceptions by group_id
    groups: dict[str, list[dict]] = defaultdict(list)
    for exc in exceptions:
        if not exc.get("is_active", True):
            continue
        group_id = str(exc.get("group_id", exc.get("id", "")))
        groups[group_id].append(exc)

    # Check each group - if ALL conditions in a group match, suppress
    for group_id, conditions in groups.items():
        if not conditions:
            continue

        # All conditions in this group must match (AND logic)
        all_match = all(
            check_exception_match(
                log,
                cond["field"],
                ExceptionOperator(cond["operator"]),
                cond["value"],
            )
            for cond in conditions
        )

        if all_match:
            return True  # This group fully matches, suppress the alert

    return False  # No group fully matched


def cluster_alerts(alerts: list[dict], settings: dict) -> list[dict]:
    """
    Cluster alerts by rule_id within time window.

    Args:
        alerts: List of alert dictionaries
        settings: Clustering settings with:
            - enabled: bool - whether clustering is enabled
            - window_minutes: int - time window for clustering

    Returns:
        List of cluster dicts with:
        - representative: first alert in cluster (by timestamp)
        - count: number of alerts in cluster
        - alert_ids: list of all alert IDs in cluster
        - time_range: tuple of (first_timestamp, last_timestamp)
    """
    if not settings.get("enabled", False):
        # When disabled, return each alert as its own cluster
        return [
            {
                "representative": alert,
                "count": 1,
                "alert_ids": [alert.get("alert_id", alert.get("id"))],
                "time_range": (alert.get("created_at"), alert.get("created_at")),
            }
            for alert in alerts
        ]

    window_minutes = settings.get("window_minutes", 60)

    # Group alerts by rule_id only
    groups: dict[str, list[dict]] = defaultdict(list)

    for alert in alerts:
        rule_id = alert.get("rule_id", "")
        groups[rule_id].append(alert)

    clusters = []
    window_delta = timedelta(minutes=window_minutes)

    for rule_id, group_alerts in groups.items():
        # Sort alerts by timestamp
        def get_timestamp(a: dict) -> datetime:
            ts = a.get("created_at")
            if ts is None:
                return datetime.min.replace(tzinfo=UTC)
            if isinstance(ts, str):
                try:
                    return date_parser.isoparse(ts)
                except (ValueError, TypeError):
                    return datetime.min.replace(tzinfo=UTC)
            return ts

        sorted_alerts = sorted(group_alerts, key=get_timestamp)

        # Cluster by time window
        current_cluster: list[dict] = []
        cluster_start: datetime | None = None

        for alert in sorted_alerts:
            alert_time = get_timestamp(alert)

            if not current_cluster:
                current_cluster = [alert]
                cluster_start = alert_time
            elif cluster_start and alert_time - cluster_start <= window_delta:
                current_cluster.append(alert)
            else:
                # Finalize current cluster and start new one
                clusters.append(_create_cluster(current_cluster))
                current_cluster = [alert]
                cluster_start = alert_time

        # Don't forget the last cluster
        if current_cluster:
            clusters.append(_create_cluster(current_cluster))

    # Sort clusters by representative's timestamp (most recent first)
    def get_cluster_time(c: dict) -> datetime:
        ts = c["time_range"][0]
        if ts is None:
            return datetime.min.replace(tzinfo=UTC)
        if isinstance(ts, str):
            try:
                return date_parser.isoparse(ts)
            except (ValueError, TypeError):
                return datetime.min.replace(tzinfo=UTC)
        return ts

    clusters.sort(key=get_cluster_time, reverse=True)

    return clusters


def _create_cluster(alerts: list[dict]) -> dict:
    """Create a cluster dict from a list of alerts."""
    # Representative is the first (oldest) alert
    representative = alerts[0]

    # Get timestamps
    timestamps = []
    for alert in alerts:
        ts = alert.get("created_at")
        if ts:
            timestamps.append(ts)

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    return {
        "representative": representative,
        "count": len(alerts),
        "alert_ids": [a.get("alert_id", a.get("id")) for a in alerts],
        "alerts": alerts,  # Include all alerts for expanded view
        "time_range": (first_ts, last_ts),
    }


ALERTS_MAPPING = {
    "settings": {
        "index.mapping.total_fields.limit": 10000,
    },
    "mappings": {
        "dynamic": True,
        "properties": {
            "alert_id": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "severity": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "status": {"type": "keyword"},  # new, acknowledged, resolved, false_positive
            "log_document": {"type": "object", "enabled": False},  # Store but don't index
            "matched_fields": {"type": "keyword"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "acknowledged_by": {"type": "keyword"},
            "acknowledged_at": {"type": "date"},
            # Threat Intelligence enrichment
            "ti_enrichment": {
                "type": "object",
                "properties": {
                    "sources_used": {"type": "keyword"},
                    "indicators": {
                        "type": "nested",
                        "properties": {
                            "indicator": {"type": "keyword"},
                            "indicator_type": {"type": "keyword"},
                            "overall_risk_level": {"type": "keyword"},
                            "overall_risk_score": {"type": "float"},
                            "highest_risk_source": {"type": "keyword"},
                            "sources_queried": {"type": "integer"},
                            "sources_with_results": {"type": "integer"},
                            "sources_with_detections": {"type": "integer"},
                            "all_categories": {"type": "keyword"},
                            "all_tags": {"type": "keyword"},
                        },
                    },
                },
            },
        }
    }
}


class AlertService:
    def __init__(self, client: OpenSearch):
        self.client = client

    def get_alerts_index_name(self, index_suffix: str) -> str:
        """Generate alerts index name for a given source."""
        return f"chad-alerts-{index_suffix}"

    def ensure_alerts_index(self, index_name: str) -> None:
        """Create alerts index if it doesn't exist."""
        if not self.client.indices.exists(index=index_name):
            self.client.indices.create(index=index_name, body=ALERTS_MAPPING)

    def match_log(
        self, percolator_index: str, log: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Run percolate query to find matching rules.

        Returns list of matching rule documents.
        """
        query = {
            "query": {
                "percolate": {
                    "field": "query",
                    "document": log,
                }
            }
        }

        try:
            result = self.client.search(index=percolator_index, body=query)
            matches = []
            for hit in result.get("hits", {}).get("hits", []):
                matches.append(hit["_source"])
            return matches
        except Exception:
            return []

    def create_alert(
        self,
        alerts_index: str,
        rule_id: str,
        rule_title: str,
        severity: str,
        tags: list[str],
        log_document: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Create and store an alert document.

        Uses deterministic alert IDs to prevent duplicates on retry.
        Same event + same rule + same minute = same alert ID.
        """
        self.ensure_alerts_index(alerts_index)

        # Generate deterministic alert ID before modifying log_document
        # This ensures same event + same rule + same minute = same alert ID
        alert_id = generate_deterministic_alert_id(rule_id, log_document)
        now = datetime.now(UTC).isoformat()

        # Extract TI enrichment to top level for querying
        ti_enrichment = log_document.pop("ti_enrichment", None)

        # Extract IOC matches to top level for display
        # Check both threat_intel.ioc_matches (standard location) and direct ioc_matches (fallback)
        ioc_matches = None
        threat_intel = log_document.get("threat_intel")
        if threat_intel and isinstance(threat_intel, dict):
            ioc_matches = threat_intel.get("ioc_matches")
        if not ioc_matches:
            # Fallback: check if ioc_matches is directly in log_document
            ioc_matches = log_document.pop("ioc_matches", None)

        alert = {
            "alert_id": alert_id,
            "rule_id": rule_id,
            "rule_title": rule_title,
            "severity": severity,
            "tags": tags,
            "status": "new",
            "log_document": log_document,
            "created_at": now,
            "updated_at": now,
        }

        # Add TI enrichment at top level if present
        if ti_enrichment:
            alert["ti_enrichment"] = ti_enrichment

        # Add IOC matches at top level if present
        if ioc_matches:
            alert["ioc_matches"] = ioc_matches

        # Use the deterministic alert_id as the document ID
        # This makes retries overwrite instead of creating duplicates
        # Use refresh=False for eventual consistency (~1 second delay)
        # This significantly improves write performance at scale
        self.client.index(
            index=alerts_index,
            id=alert_id,
            body=alert,
            refresh=False,
        )

        return alert

    def bulk_create_alerts(
        self,
        alerts_index: str,
        alerts: list[dict[str, Any]],
    ) -> list[str]:
        """
        Create multiple alerts in a single bulk operation.

        Uses OpenSearch bulk API for efficient writes at scale.
        Each alert uses deterministic ID to prevent duplicates on retry.

        Args:
            alerts_index: Target OpenSearch index
            alerts: List of alert documents to create. Each must have:
                - rule_id: str
                - rule_title: str
                - severity: str
                - log_document: dict

        Returns:
            List of created alert IDs
        """
        if not alerts:
            return []

        self.ensure_alerts_index(alerts_index)

        bulk_body = []
        alert_ids = []
        now = datetime.now(UTC).isoformat()

        for alert_data in alerts:
            alert_id = generate_deterministic_alert_id(
                alert_data["rule_id"],
                alert_data.get("log_document", {}),
            )
            alert_ids.append(alert_id)

            # Index action
            bulk_body.append({"index": {"_index": alerts_index, "_id": alert_id}})

            # Extract TI enrichment to top level for querying
            log_doc = alert_data.get("log_document", {})
            ti_enrichment = log_doc.pop("ti_enrichment", None) if isinstance(log_doc, dict) else None

            # Document
            alert_doc = {
                "alert_id": alert_id,
                "rule_id": alert_data["rule_id"],
                "rule_title": alert_data["rule_title"],
                "severity": alert_data["severity"],
                "tags": alert_data.get("tags", []),
                "status": "new",
                "log_document": log_doc,
                "created_at": now,
                "updated_at": now,
            }

            if ti_enrichment:
                alert_doc["ti_enrichment"] = ti_enrichment

            bulk_body.append(alert_doc)

        if bulk_body:
            result = self.client.bulk(body=bulk_body, refresh=False)
            if result.get("errors"):
                logger.warning("Some bulk alert writes failed: %s", result)

        return alert_ids

    def get_alerts(
        self,
        index_pattern: str = "chad-alerts-*",
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        owner_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        exclude_ioc: bool = False,
    ) -> dict[str, Any]:
        """Query alerts with filters."""
        must = []

        if status:
            must.append({"term": {"status": status}})
        if severity:
            must.append({"term": {"severity": severity}})
        if rule_id:
            must.append({"term": {"rule_id": rule_id}})
        if owner_id:
            # Use .keyword suffix for exact matching (dynamic mapping creates text + keyword multifield)
            must.append({"term": {"owner_id.keyword": owner_id}})
        if exclude_ioc:
            must.append({"bool": {"must_not": [{"term": {"rule_id": "ioc-detection"}}]}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"created_at": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }

        try:
            result = self.client.search(index=index_pattern, body=query)
            alerts = []
            for hit in result["hits"]["hits"]:
                alert = hit["_source"]
                # Extract ioc_matches from log_document if not at top level (backward compat)
                if not alert.get("ioc_matches"):
                    log_doc = alert.get("log_document", {})
                    if log_doc.get("ioc_matches"):
                        alert["ioc_matches"] = log_doc["ioc_matches"]
                    elif log_doc.get("threat_intel", {}).get("ioc_matches"):
                        alert["ioc_matches"] = log_doc["threat_intel"]["ioc_matches"]
                alerts.append(alert)
            return {
                "total": result["hits"]["total"]["value"],
                "alerts": alerts,
            }
        except Exception as e:
            # Only swallow "index not found" errors, re-raise everything else
            error_str = str(e)
            if "index_not_found_exception" in error_str or "no such index" in error_str.lower():
                return {"total": 0, "alerts": []}
            raise

    async def get_alerts_cached(
        self,
        cache: "AlertCache",
        index_pattern: str = "chad-alerts-*",
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        owner_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        exclude_ioc: bool = False,
    ) -> dict[str, Any]:
        """Query alerts with Redis cache fallback.

        Tries OpenSearch first, falls back to cache on failure.
        Raises OpenSearchUnavailableError if both fail.
        """
        from app.core.exceptions import OpenSearchUnavailableError

        cache_kwargs = dict(
            status=status, severity=severity, rule_id=rule_id,
            owner_id=owner_id, index_pattern=index_pattern,
            limit=limit, offset=offset, exclude_ioc=exclude_ioc,
        )

        try:
            result = self.get_alerts(
                index_pattern=index_pattern,
                status=status, severity=severity,
                rule_id=rule_id, owner_id=owner_id,
                limit=limit, offset=offset,
                exclude_ioc=exclude_ioc,
            )
            # Cache the fresh result
            await cache.set_alerts(result, **cache_kwargs)
            result["cached"] = False
            result["opensearch_available"] = True
            return result
        except Exception as os_error:
            logger.warning("OpenSearch query failed: %s", os_error)
            # Try cache fallback
            cached = await cache.get_alerts(**cache_kwargs)
            if cached is not None:
                cached["cached"] = True
                cached["opensearch_available"] = False
                return cached
            raise OpenSearchUnavailableError(str(os_error))

    def get_alert(
        self,
        index_pattern: str,
        alert_id: str,
    ) -> dict[str, Any] | None:
        """Get a single alert by ID."""
        try:
            result = self.client.search(
                index=index_pattern,
                body={"query": {"term": {"alert_id": alert_id}}},
            )
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                alert = hits[0]["_source"]
                # Extract ioc_matches from log_document if not at top level (backward compat)
                if not alert.get("ioc_matches"):
                    log_doc = alert.get("log_document", {})
                    if log_doc.get("ioc_matches"):
                        alert["ioc_matches"] = log_doc["ioc_matches"]
                    elif log_doc.get("threat_intel", {}).get("ioc_matches"):
                        alert["ioc_matches"] = log_doc["threat_intel"]["ioc_matches"]
                return alert
            return None
        except Exception:
            return None

    def update_alert_status(
        self,
        alerts_index: str,
        alert_id: str,
        status: str,
        user_id: str | None = None,
    ) -> bool:
        """Update alert status (acknowledge, resolve, mark false positive)."""
        now = datetime.now(UTC).isoformat()
        update = {
            "status": status,
            "updated_at": now,
        }

        if status == "acknowledged" and user_id:
            update["acknowledged_by"] = user_id
            update["acknowledged_at"] = now

        try:
            self.client.update(
                index=alerts_index,
                id=alert_id,
                body={"doc": update},
                refresh=True,
            )
            return True
        except Exception:
            return False

    def get_alert_counts(
        self,
        index_pattern: str = "chad-alerts-*",
    ) -> dict[str, Any]:
        """Get alert counts by status and severity for dashboard."""
        query = {
            "size": 0,
            "aggs": {
                "by_status": {
                    "terms": {"field": "status", "size": 10}
                },
                "by_severity": {
                    "terms": {"field": "severity", "size": 10}
                },
                "recent_24h": {
                    "filter": {
                        "range": {
                            "created_at": {"gte": "now-24h"}
                        }
                    }
                }
            }
        }

        try:
            result = self.client.search(index=index_pattern, body=query)
            aggs = result.get("aggregations", {})

            return {
                "total": result["hits"]["total"]["value"],
                "by_status": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_status", {}).get("buckets", [])
                },
                "by_severity": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_severity", {}).get("buckets", [])
                },
                "last_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            }
        except Exception:
            return {
                "total": 0,
                "by_status": {},
                "by_severity": {},
                "last_24h": 0,
            }

    async def delete_alert(
        self,
        db: AsyncSession,
        alert_id: UUID,
        current_user_id: UUID,
        ip_address: str
    ) -> bool:
        """Delete an alert.

        Args:
            db: Database session
            alert_id: OpenSearch alert document ID (UUID)
            current_user_id: User performing the deletion
            ip_address: Client IP for audit

        Returns:
            True if deleted, False if not found
        """
        from sqlalchemy import delete as sql_delete
        from sqlalchemy import select

        # Get alert from database by alert_id (OpenSearch document ID)
        result = await db.execute(select(Alert).where(Alert.alert_id == str(alert_id)))
        alert = result.scalar_one_or_none()

        # If not in database, try to delete from OpenSearch only
        if not alert:
            # Check if alert exists in OpenSearch
            try:
                # Search for the alert across all alert indices
                search_result = self.client.search(
                    index="chad-alerts-*",
                    body={"query": {"term": {"alert_id": str(alert_id)}}}
                )
                hits = search_result.get("hits", {}).get("hits", [])

                if not hits:
                    return False

                # Alert exists in OpenSearch but not in database
                # Delete from OpenSearch and create minimal audit log
                hit = hits[0]
                alert_index = hit["_index"]
                alert_source = hit["_source"]

                self.client.delete(index=alert_index, id=str(alert_id), refresh=True)

                # Create audit log entry (alert has been deleted)
                from app.services.audit import audit_log
                await audit_log(
                    db,
                    current_user_id,
                    "alert.delete",
                    "alert",
                    str(alert_id),
                    {
                        "title": alert_source.get("title", alert_source.get("rule_title", "Unknown")),
                        "note": "Alert deleted from OpenSearch only (no DB record)"
                    },
                    ip_address=ip_address
                )
                await db.commit()

                return True
            except Exception as e:
                logger.error("Failed to delete alert from OpenSearch: %s", e)
                await system_log_service.log_error(
                    db,
                    category=LogCategory.ALERTS,
                    service="alerts",
                    message="Failed to delete alert from OpenSearch",
                    details={
                        "alert_id": str(alert_id),
                        "error": str(e),
                        "error_type": type(e).__name__,
                    },
                )
                return False

        # Alert exists in database, delete from both places
        # Log before delete
        from app.services.audit import audit_log
        await audit_log(
            db,
            current_user_id,
            "alert.delete",
            "alert",
            str(alert_id),
            {"title": alert.title, "rule_id": str(alert.rule_id)},
            ip_address=ip_address
        )

        # Delete from OpenSearch
        try:
            self.client.delete(
                index=alert.alert_index,
                id=alert.alert_id,
                refresh=True
            )
        except Exception as e:
            logger.warning("Failed to delete alert from OpenSearch: %s", e)
            await system_log_service.log_warning(
                db,
                category=LogCategory.ALERTS,
                service="alerts",
                message="Failed to delete alert from OpenSearch (DB record will still be deleted)",
                details={
                    "alert_id": str(alert_id),
                    "alert_index": alert.alert_index,
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )

        # Delete from database
        await db.execute(sql_delete(Alert).where(Alert.alert_id == str(alert_id)))
        await db.commit()

        return True
