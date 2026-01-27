"""
Alert service - handles alert creation, storage, and retrieval.

Alerts are stored in OpenSearch with the following structure:
- chad-alerts-{index_suffix}: Index per log source
- Each alert contains: rule info, matched log, timestamp, status
"""

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from opensearchpy import OpenSearch

from app.models.rule_exception import ExceptionOperator


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
    """Check if an alert should be suppressed based on active exceptions."""
    for exc in exceptions:
        if not exc.get("is_active", True):
            continue

        if check_exception_match(
            log,
            exc["field"],
            ExceptionOperator(exc["operator"]),
            exc["value"],
        ):
            return True

    return False

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
        """Create and store an alert document."""
        self.ensure_alerts_index(alerts_index)

        alert_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()

        # Extract TI enrichment to top level for querying
        ti_enrichment = log_document.pop("ti_enrichment", None)

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

        self.client.index(
            index=alerts_index,
            id=alert_id,
            body=alert,
            refresh=True,
        )

        return alert

    def get_alerts(
        self,
        index_pattern: str = "chad-alerts-*",
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Query alerts with filters."""
        must = []

        if status:
            must.append({"term": {"status": status}})
        if severity:
            must.append({"term": {"severity": severity}})
        if rule_id:
            must.append({"term": {"rule_id": rule_id}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"created_at": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }

        try:
            result = self.client.search(index=index_pattern, body=query)
            return {
                "total": result["hits"]["total"]["value"],
                "alerts": [hit["_source"] for hit in result["hits"]["hits"]],
            }
        except Exception:
            # Index may not exist yet
            return {"total": 0, "alerts": []}

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
                return hits[0]["_source"]
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

    def delete_alert(
        self,
        db: AsyncSession,
        alert_id: UUID,
        current_user_id: UUID,
        ip_address: str
    ) -> bool:
        """Delete an alert.

        Args:
            db: Database session
            alert_id: Alert ID to delete
            current_user_id: User performing the deletion
            ip_address: Client IP for audit

        Returns:
            True if deleted, False if not found
        """
        from sqlalchemy import delete as sql_delete

        # Get alert for audit log
        alert = db.get(Alert, alert_id)
        if not alert:
            return False

        # Log before delete
        from app.services.audit import audit_log
        import asyncio
        asyncio.create_task(audit_log(
            db,
            current_user_id,
            "alert.delete",
            "alert",
            str(alert_id),
            {"title": alert.title, "rule_id": str(alert.rule_id)},
            ip_address=ip_address
        ))

        # Delete from OpenSearch
        try:
            self.client.delete(
                index=alert.alert_index,
                id=alert.alert_id
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to delete alert from OpenSearch: {e}")

        # Delete from database
        await db.execute(sql_delete(Alert).where(Alert.id == alert_id))
        await db.commit()

        return True
