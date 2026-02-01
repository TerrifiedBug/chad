"""Pull-based detection service for querying OpenSearch on schedule."""

from datetime import datetime, timezone, timedelta
from typing import Any
import logging

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


def get_settings():
    """Get application settings (for easier mocking in tests)."""
    from app.core.config import settings
    return settings


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


async def schedule_pull_jobs(scheduler, index_patterns: list) -> None:
    """
    Schedule polling jobs for pull-mode index patterns.

    In pull-only deployment (CHAD_MODE=pull), all patterns are scheduled.
    In full deployment, only patterns with mode='pull' are scheduled.

    Args:
        scheduler: APScheduler instance
        index_patterns: List of IndexPattern models
    """
    settings = get_settings()

    for pattern in index_patterns:
        # In pull-only mode, schedule all patterns
        # In full mode, only schedule pull patterns
        if not settings.is_pull_only and pattern.mode != "pull":
            continue

        job_id = f"pull_poll_{pattern.id}"

        # Remove existing job if any
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass

        # Add new job with pattern's poll interval
        scheduler.add_job(
            run_poll_job,
            "interval",
            minutes=pattern.poll_interval_minutes,
            id=job_id,
            args=[str(pattern.id)],
            replace_existing=True,
        )
        logger.info(
            f"Scheduled pull job for {pattern.pattern} every {pattern.poll_interval_minutes} min"
        )


async def run_poll_job(index_pattern_id: str) -> None:
    """
    Execute a single poll job for an index pattern.

    Args:
        index_pattern_id: UUID of the index pattern to poll
    """
    from app.db.session import async_session_maker
    from app.models.index_pattern import IndexPattern
    from app.models.poll_state import IndexPatternPollState
    from app.models.rule import Rule, RuleStatus
    from app.services.sigma import SigmaService
    from app.services.alerts import AlertService
    from app.services.opensearch import get_opensearch_client
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    logger.info(f"Running pull poll for index pattern {index_pattern_id}")

    async with async_session_maker() as session:
        try:
            # Get index pattern with poll state
            result = await session.execute(
                select(IndexPattern)
                .where(IndexPattern.id == index_pattern_id)
                .options(selectinload(IndexPattern.poll_state))
            )
            index_pattern = result.scalar_one_or_none()

            if not index_pattern:
                logger.error(f"Index pattern {index_pattern_id} not found")
                return

            # Get deployed rules for this pattern
            rules_result = await session.execute(
                select(Rule)
                .where(Rule.index_pattern_id == index_pattern.id)
                .where(Rule.status == RuleStatus.DEPLOYED)
            )
            rules = list(rules_result.scalars().all())

            if not rules:
                logger.debug(f"No deployed rules for {index_pattern.pattern}")
                return

            # Get last poll time
            last_poll = None
            if index_pattern.poll_state:
                last_poll = index_pattern.poll_state.last_poll_at

            # Execute poll
            client = get_opensearch_client()
            detector = PullDetector(client=client)
            sigma_service = SigmaService()
            alert_service = AlertService(client=client)

            poll_result = await detector.poll_index_pattern(
                index_pattern=index_pattern,
                rules=rules,
                sigma_service=sigma_service,
                alert_service=alert_service,
                last_poll=last_poll,
            )

            # Update poll state
            now = datetime.now(timezone.utc)
            if index_pattern.poll_state:
                index_pattern.poll_state.last_poll_at = now
                index_pattern.poll_state.last_poll_status = (
                    "error" if poll_result["errors"] else "success"
                )
                index_pattern.poll_state.last_error = (
                    str(poll_result["errors"]) if poll_result["errors"] else None
                )
                index_pattern.poll_state.updated_at = now
            else:
                poll_state = IndexPatternPollState(
                    index_pattern_id=index_pattern.id,
                    last_poll_at=now,
                    last_poll_status="error" if poll_result["errors"] else "success",
                    last_error=str(poll_result["errors"]) if poll_result["errors"] else None,
                )
                session.add(poll_state)

            await session.commit()

            logger.info(
                f"Poll complete for {index_pattern.pattern}: "
                f"{poll_result['matches']} matches, {len(poll_result['errors'])} errors"
            )

        except Exception as e:
            logger.error(f"Poll job failed for {index_pattern_id}: {e}")
            raise
