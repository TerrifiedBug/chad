"""Pull-based detection service for querying OpenSearch on schedule."""

from datetime import datetime, timezone, timedelta
from typing import Any
import logging

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


class PullDetector:
    """Executes scheduled queries against OpenSearch for pull mode detection."""

    def __init__(self, client: OpenSearch):
        self.client = client

    def build_time_filtered_query(
        self,
        base_query: dict[str, Any],
        last_poll: datetime | None,
        now: datetime,
    ) -> dict[str, Any]:
        """
        Wrap the base query with a time filter.

        Args:
            base_query: The original DSL query from Sigma translation
            last_poll: Last successful poll time, or None for first poll
            now: Current time

        Returns:
            Query with time range filter added
        """
        # If no last poll, look back 1 hour as default window
        if last_poll is None:
            last_poll = now - timedelta(hours=1)

        time_filter = {
            "range": {
                "@timestamp": {
                    "gt": last_poll.isoformat(),
                    "lte": now.isoformat(),
                }
            }
        }

        # Wrap original query in bool.must with time filter
        wrapped = {
            "bool": {
                "must": [
                    base_query,
                    time_filter,
                ]
            }
        }

        return wrapped

    async def poll_index_pattern(
        self,
        index_pattern,  # IndexPattern model
        rules: list,  # List of Rule models
        sigma_service,  # SigmaService
        alert_service,  # AlertService
        last_poll: datetime | None,
    ) -> dict[str, Any]:
        """
        Poll an index pattern for all deployed rules.

        Args:
            index_pattern: The IndexPattern to poll
            rules: List of deployed Rule models
            sigma_service: Service for translating Sigma to DSL
            alert_service: Service for creating alerts
            last_poll: Last successful poll time

        Returns:
            Dict with poll results: {"matches": int, "errors": list}
        """
        now = datetime.now(timezone.utc)
        total_matches = 0
        errors = []

        for rule in rules:
            try:
                # Translate rule to DSL
                base_query = sigma_service.translate_rule(rule.yaml_content)

                # Add time filter
                query = self.build_time_filtered_query(base_query, last_poll, now)

                # Execute search
                response = self.client.search(
                    index=index_pattern.pattern,
                    body={"query": query, "size": 1000},
                )

                hits = response.get("hits", {}).get("hits", [])

                # Create alert for each match
                for hit in hits:
                    await alert_service.create_alert(
                        rule_id=str(rule.id),
                        rule_title=rule.title,
                        severity=rule.severity,
                        tags=[],
                        log_document=hit["_source"],
                    )
                    total_matches += 1

            except Exception as e:
                logger.error(f"Error polling rule {rule.id}: {e}")
                errors.append({"rule_id": str(rule.id), "error": str(e)})

        return {"matches": total_matches, "errors": errors}
