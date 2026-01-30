"""Log processor for worker batch processing."""

import logging
import time
from typing import Any

from opensearchpy import OpenSearch

from app.services.alerts import AlertService
from app.services.batch_percolate import batch_percolate_logs

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

    async def process_batch(
        self,
        index_suffix: str,
        logs: list[dict[str, Any]],
    ) -> dict:
        """
        Process a batch of logs.

        Uses batch percolation for efficient rule matching and bulk
        alert creation for efficient writes.

        Args:
            index_suffix: The index pattern suffix
            logs: List of log documents

        Returns:
            Processing stats
        """
        start_time = time.time()
        percolator_index = f"chad-percolator-{index_suffix}"
        alerts_index = f"chad-alerts-{index_suffix}"

        # Batch percolate all logs at once
        matches_by_log = batch_percolate_logs(
            self.os_client,
            percolator_index,
            logs,
        )

        # Collect all alerts to create
        alerts_to_create = []
        total_matches = 0

        for log_idx, rule_matches in matches_by_log.items():
            log = logs[log_idx]
            total_matches += len(rule_matches)

            for rule in rule_matches:
                alert_data = {
                    "rule_id": rule.get("rule_id"),
                    "rule_title": rule.get("title"),
                    "severity": rule.get("severity", "medium"),
                    "tags": rule.get("tags", []),
                    "log_document": log,
                }
                alerts_to_create.append(alert_data)

        # Bulk create alerts
        if alerts_to_create:
            self.alert_service.bulk_create_alerts(alerts_index, alerts_to_create)

        elapsed = time.time() - start_time
        logger.info(
            f"Processed batch: {len(logs)} logs, {total_matches} matches, "
            f"{len(alerts_to_create)} alerts in {elapsed:.2f}s"
        )

        return {
            "logs_processed": len(logs),
            "matches": total_matches,
            "alerts_created": len(alerts_to_create),
            "elapsed_seconds": elapsed,
        }
