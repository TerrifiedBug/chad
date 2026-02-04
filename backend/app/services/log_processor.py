"""Log processor for worker batch processing."""

import logging
import time
from typing import Any
from uuid import UUID

import yaml
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.models.rule_exception import RuleException
from app.services.alert_pubsub import publish_alert
from app.services.alerts import AlertService, should_suppress_alert
from app.services.batch_percolate import batch_percolate_logs
from app.services.correlation import check_correlation
from app.services.enrichment import enrich_alert
from app.services.notification import send_alert_notification
from app.services.settings import get_app_url
from app.services.ti.ioc_detector import IOCDetector

logger = logging.getLogger(__name__)


class LogProcessor:
    """Processes batches of logs from the queue."""

    def __init__(
        self,
        os_client: OpenSearch,
        db_session_factory,
    ):
        self.os_client = os_client
        self.db_session_factory = db_session_factory
        self.alert_service = AlertService(os_client)
        self.ioc_detector = IOCDetector()

    async def _get_index_pattern(
        self,
        db: AsyncSession,
        index_suffix: str,
    ) -> IndexPattern | None:
        """Look up index pattern by suffix/name."""
        result = await db.execute(
            select(IndexPattern).where(IndexPattern.name == index_suffix)
        )
        return result.scalar_one_or_none()

    async def _get_rule_exceptions(
        self,
        db: AsyncSession,
        rule_id: str,
        cache: dict[str, list[dict]],
    ) -> list[dict]:
        """Get exceptions for a rule, with caching."""
        if rule_id in cache:
            return cache[rule_id]

        try:
            rule_uuid = UUID(rule_id)
            result = await db.execute(
                select(RuleException).where(
                    RuleException.rule_id == rule_uuid,
                    RuleException.is_active.is_(True),
                )
            )
            exceptions = result.scalars().all()
            cache[rule_id] = [
                {
                    "field": e.field,
                    "operator": e.operator.value,
                    "value": e.value,
                    "is_active": e.is_active,
                    "group_id": str(e.group_id) if e.group_id else str(e.id),
                }
                for e in exceptions
            ]
        except (ValueError, Exception) as e:
            logger.debug("Failed to load exceptions for rule %s: %s", rule_id, e)
            cache[rule_id] = []

        return cache[rule_id]

    async def process_batch(
        self,
        db: AsyncSession,
        index_suffix: str,
        logs: list[dict[str, Any]],
    ) -> dict:
        """
        Process a batch of logs.

        Uses batch percolation for efficient rule matching and bulk
        alert creation for efficient writes.

        Includes:
        - Exception checking (suppression)
        - Rule enabled checking
        - GeoIP/TI enrichment
        - Correlation checking
        - Notification dispatch

        Args:
            db: Database session
            index_suffix: The index pattern suffix
            logs: List of log documents

        Returns:
            Processing stats
        """
        start_time = time.time()
        percolator_index = f"chad-percolator-{index_suffix}"
        alerts_index = f"chad-alerts-{index_suffix}"

        # Look up index pattern for enrichment config
        index_pattern = await self._get_index_pattern(db, index_suffix)
        if not index_pattern:
            logger.warning("No index pattern found for '%s', processing without enrichment", index_suffix)

        # Cache for rule exceptions (avoid repeated DB queries)
        rule_exceptions_cache: dict[str, list[dict]] = {}

        # IOC detection for Push Mode (check all logs against Redis IOC cache)
        ioc_matches_by_log: dict[int, list[dict]] = {}
        ioc_detection_enabled = (
            index_pattern
            and index_pattern.ioc_detection_enabled
            and index_pattern.ioc_field_mappings
        )

        if ioc_detection_enabled:
            for log_idx, log in enumerate(logs):
                try:
                    matches = await self.ioc_detector.detect_iocs(
                        log, index_pattern.ioc_field_mappings
                    )
                    if matches:
                        ioc_matches_by_log[log_idx] = [m.to_dict() for m in matches]
                except Exception as e:
                    logger.debug("IOC detection failed for log %d: %s", log_idx, e)

        # Batch percolate all logs at once
        matches_by_log = batch_percolate_logs(
            self.os_client,
            percolator_index,
            logs,
        )

        # Collect all alerts to create
        alerts_created = []
        total_matches = 0
        suppressed_count = 0
        disabled_count = 0
        # Track which log indices actually created Sigma alerts (for duplicate prevention)
        logs_with_sigma_alerts: set[int] = set()

        # Get app URL for notification links
        app_url = await get_app_url(db)

        for log_idx, rule_matches in matches_by_log.items():
            log = logs[log_idx]

            for rule in rule_matches:
                rule_id = rule.get("rule_id")
                if not rule_id:
                    continue

                # Check if rule is enabled
                if not rule.get("enabled", True):
                    disabled_count += 1
                    continue

                # Get exceptions for this rule
                exceptions = await self._get_rule_exceptions(db, rule_id, rule_exceptions_cache)

                # Check if alert should be suppressed
                if should_suppress_alert(log, exceptions):
                    suppressed_count += 1
                    continue

                # Enrich log with GeoIP/TI data if configured
                if index_pattern:
                    try:
                        enriched_log = await enrich_alert(db, log, index_pattern)
                    except Exception as e:
                        logger.warning("Enrichment failed for log: %s", e)
                        enriched_log = log
                else:
                    enriched_log = log

                # Add IOC matches to enriched log if any were found
                if log_idx in ioc_matches_by_log:
                    enriched_log["threat_intel"] = {
                        "ioc_matches": ioc_matches_by_log[log_idx],
                        "has_ioc_match": True,
                    }

                # Create alert
                try:
                    alert = self.alert_service.create_alert(
                        alerts_index=alerts_index,
                        rule_id=rule_id,
                        rule_title=rule.get("rule_title"),
                        severity=rule.get("severity", "medium"),
                        tags=rule.get("tags", []),
                        log_document=enriched_log,
                    )
                    alerts_created.append(alert)
                    total_matches += 1
                    logs_with_sigma_alerts.add(log_idx)

                    # Check for correlation triggers
                    await self._check_correlations(
                        db=db,
                        rule_id=rule_id,
                        enriched_log=enriched_log,
                        alert=alert,
                        alerts_index=alerts_index,
                        alerts_created=alerts_created,
                    )

                except Exception as e:
                    logger.error("Failed to create alert for rule %s: %s", rule_id, e)
                    continue

        # Create IOC-only alerts for logs that matched IOCs but didn't create Sigma alerts
        ioc_only_alerts = 0
        if ioc_detection_enabled and ioc_matches_by_log:
            for log_idx, ioc_matches in ioc_matches_by_log.items():
                if log_idx in logs_with_sigma_alerts:
                    # Skip - already has a Sigma alert (IOC info is embedded in that alert)
                    continue

                log = logs[log_idx]

                # Enrich the log
                if index_pattern:
                    try:
                        enriched_log = await enrich_alert(db, log, index_pattern)
                    except Exception as e:
                        logger.debug("Enrichment failed for IOC-only log: %s", e)
                        enriched_log = log
                else:
                    enriched_log = log

                # Add IOC match info
                enriched_log["threat_intel"] = {
                    "ioc_matches": ioc_matches,
                    "has_ioc_match": True,
                }

                # Determine severity from highest threat level in matches
                threat_levels = [m.get("threat_level", "unknown") for m in ioc_matches]
                if "high" in threat_levels:
                    severity = "high"
                elif "medium" in threat_levels:
                    severity = "medium"
                else:
                    severity = "low"

                # Get IOC type and title from first match
                first_match = ioc_matches[0] if ioc_matches else {}
                ioc_type = first_match.get("ioc_type", "unknown")
                # Use MISP event info as title if available, otherwise fall back to IOC value
                event_info = first_match.get("misp_event_info")
                ioc_title = event_info if event_info else f"IOC Match: {first_match.get('value', ioc_type)}"

                # Build tags from IOC matches
                tags = ["ioc-match", f"ioc-type:{ioc_type}"]
                for match in ioc_matches:
                    if match.get("misp_event_id"):
                        tags.append(f"misp:{match['misp_event_id']}")
                    tags.extend(match.get("tags", []))
                # Deduplicate tags
                tags = list(dict.fromkeys(tags))

                try:
                    ioc_alert = self.alert_service.create_alert(
                        alerts_index=alerts_index,
                        rule_id="ioc-detection",
                        rule_title=ioc_title,
                        severity=severity,
                        tags=tags,
                        log_document=enriched_log,
                    )
                    alerts_created.append(ioc_alert)
                    ioc_only_alerts += 1
                except Exception as e:
                    logger.error("Failed to create IOC-only alert: %s", e)

            if ioc_only_alerts > 0:
                logger.info("Created %d IOC-only alerts (Push Mode)", ioc_only_alerts)

        # Broadcast alerts via WebSocket (Redis pub/sub for cross-worker)
        if alerts_created:
            await self._broadcast_alerts(alerts_created)

        # Send notifications for created alerts
        if alerts_created:
            await self._send_notifications(db, alerts_created, app_url)

        elapsed = time.time() - start_time
        logger.info(
            "Processed batch: %d logs, %d matches, %d alerts, %d suppressed, %d disabled in %.2fs",
            len(logs),
            total_matches,
            len(alerts_created),
            suppressed_count,
            disabled_count,
            elapsed,
        )

        return {
            "logs_processed": len(logs),
            "matches": total_matches,
            "alerts_created": len(alerts_created),
            "suppressed": suppressed_count,
            "disabled": disabled_count,
            "elapsed_seconds": elapsed,
        }

    async def _check_correlations(
        self,
        db: AsyncSession,
        rule_id: str,
        enriched_log: dict,
        alert: dict,
        alerts_index: str,
        alerts_created: list,
    ):
        """Check correlation rules and create correlation alerts if triggered."""
        try:
            triggered_correlations = await check_correlation(
                db,
                rule_id=UUID(rule_id),
                log_document=enriched_log,
                alert_id=alert["alert_id"],
            )

            if not triggered_correlations:
                return

            for corr in triggered_correlations:
                # Fetch MITRE tags from linked sigma rules
                correlation_tags = ["correlation"]
                rule_a_title = None
                rule_b_title = None

                rule_a_id = corr.get("rule_a_id")
                rule_b_id = corr.get("rule_b_id")

                if rule_a_id:
                    rule_a_title, tags = await self._get_rule_tags(db, rule_a_id)
                    correlation_tags.extend(tags)

                if rule_b_id:
                    rule_b_title, tags = await self._get_rule_tags(db, rule_b_id)
                    correlation_tags.extend(tags)

                # Deduplicate tags
                unique_tags = list(dict.fromkeys(correlation_tags))

                # Create correlation alert
                correlation_alert = self.alert_service.create_alert(
                    alerts_index=alerts_index,
                    rule_id=corr["correlation_rule_id"],
                    rule_title=corr["correlation_name"],
                    severity=corr.get("severity", "high"),
                    tags=unique_tags,
                    log_document={
                        "correlation": {
                            "correlation_rule_id": corr["correlation_rule_id"],
                            "correlation_name": corr["correlation_name"],
                            "first_alert_id": corr.get("first_alert_id"),
                            "second_alert_id": corr.get("second_alert_id"),
                            "rule_a_id": corr.get("rule_a_id"),
                            "rule_b_id": corr.get("rule_b_id"),
                            "rule_a_title": rule_a_title,
                            "rule_b_title": rule_b_title,
                            "entity_field": corr.get("entity_field"),
                            "entity_field_type": corr.get("entity_field_type", "sigma"),
                            "entity_value": corr.get("entity_value"),
                            "first_triggered_at": corr.get("first_triggered_at"),
                            "second_triggered_at": corr.get("second_triggered_at"),
                        },
                        "@timestamp": enriched_log.get("@timestamp"),
                    },
                )
                alerts_created.append(correlation_alert)

                logger.info(
                    "Correlation alert created: %s (entity: %s)",
                    corr["correlation_name"],
                    corr.get("entity_value"),
                )

        except Exception as e:
            logger.error("Correlation check failed: %s", e)

    async def _get_rule_tags(self, db: AsyncSession, rule_id: str) -> tuple[str | None, list[str]]:
        """Get rule title and MITRE tags from a rule."""
        try:
            result = await db.execute(
                select(Rule).where(Rule.id == UUID(rule_id))
            )
            rule = result.scalar_one_or_none()
            if rule:
                title = rule.title
                tags = []
                if rule.yaml_content:
                    try:
                        parsed = yaml.safe_load(rule.yaml_content)
                        if parsed and isinstance(parsed, dict):
                            tags = parsed.get("tags", []) or []
                    except yaml.YAMLError as e:
                        # Invalid YAML in rule content - return title without tags
                        logger.debug("Failed to parse rule YAML for tags: %s", e)
                return title, tags
        except Exception as e:
            # Database query failed - return empty result
            logger.debug("Failed to get rule info: %s", e)
        return None, []

    async def _broadcast_alerts(self, alerts: list[dict]):
        """Broadcast alerts via Redis pub/sub for WebSocket delivery."""
        for alert in alerts:
            try:
                alert_data = {
                    "alert_id": str(alert.get("alert_id", "")),
                    "rule_id": str(alert.get("rule_id", "")),
                    "rule_title": alert.get("rule_title", "Unknown Rule"),
                    "severity": alert.get("severity", "medium"),
                    "timestamp": alert.get("created_at", ""),
                    "matched_log": alert.get("log_document", {}),
                }
                await publish_alert(alert_data)
            except Exception as e:
                logger.warning("Failed to broadcast alert %s: %s", alert.get('alert_id'), e)

    async def _send_notifications(
        self,
        db: AsyncSession,
        alerts: list[dict],
        app_url: str | None,
    ):
        """Send notifications for created alerts."""
        for alert in alerts:
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
                logger.warning("Failed to send notification for alert %s: %s", alert['alert_id'], e)
