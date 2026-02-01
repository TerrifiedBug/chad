"""Pull-based detection service for querying OpenSearch on schedule."""

from datetime import datetime, timezone, timedelta
from typing import Any
import logging
import time

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)

# Default constants for retry logic (used when settings not loaded)
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY_SECONDS = 5
DEFAULT_CONSECUTIVE_FAILURES_WARNING = 3
DEFAULT_CONSECUTIVE_FAILURES_CRITICAL = 10


def get_settings():
    """Get application settings (for easier mocking in tests)."""
    from app.core.config import settings
    return settings


async def get_pull_mode_settings(session) -> dict[str, int]:
    """
    Get pull mode settings from the database.

    Args:
        session: SQLAlchemy async session

    Returns:
        Dict with pull mode settings
    """
    from app.services.settings import get_setting

    pull_settings = await get_setting(session, "pull_mode")
    if not pull_settings:
        pull_settings = {}

    return {
        "max_retries": pull_settings.get("max_retries", DEFAULT_MAX_RETRIES),
        "retry_delay_seconds": pull_settings.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS),
        "consecutive_failures_warning": pull_settings.get(
            "consecutive_failures_warning", DEFAULT_CONSECUTIVE_FAILURES_WARNING
        ),
        "consecutive_failures_critical": pull_settings.get(
            "consecutive_failures_critical", DEFAULT_CONSECUTIVE_FAILURES_CRITICAL
        ),
    }


class PullDetector:
    """Executes scheduled queries against OpenSearch for pull mode detection."""

    def __init__(self, client: OpenSearch, settings: dict[str, int] | None = None):
        self.client = client
        self._settings = settings or {
            "max_retries": DEFAULT_MAX_RETRIES,
            "retry_delay_seconds": DEFAULT_RETRY_DELAY_SECONDS,
            "consecutive_failures_warning": DEFAULT_CONSECUTIVE_FAILURES_WARNING,
            "consecutive_failures_critical": DEFAULT_CONSECUTIVE_FAILURES_CRITICAL,
        }

    @property
    def max_retries(self) -> int:
        return self._settings.get("max_retries", DEFAULT_MAX_RETRIES)

    @property
    def retry_delay_seconds(self) -> int:
        return self._settings.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS)

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

    def _execute_search_with_retry(
        self,
        index_pattern: str,
        query: dict[str, Any],
        rule_id: str,
    ) -> dict[str, Any]:
        """
        Execute OpenSearch query with retry logic.

        Args:
            index_pattern: OpenSearch index pattern
            query: DSL query to execute
            rule_id: Rule ID for logging

        Returns:
            OpenSearch response dict

        Raises:
            Exception: If all retries fail
        """
        last_error = None
        max_retries = self.max_retries
        retry_delay = self.retry_delay_seconds

        for attempt in range(max_retries):
            try:
                return self.client.search(
                    index=index_pattern,
                    body={"query": query, "size": 1000},
                )
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    logger.warning(
                        f"OpenSearch query failed for rule {rule_id} (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    time.sleep(retry_delay)
                else:
                    logger.error(
                        f"OpenSearch query failed for rule {rule_id} after {max_retries} attempts: {e}"
                    )
        raise last_error

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
            Dict with poll results: {"matches": int, "errors": list, "events_scanned": int, "duration_ms": int}
        """
        start_time = time.monotonic()
        now = datetime.now(timezone.utc)
        total_matches = 0
        total_events_scanned = 0
        errors = []

        for rule in rules:
            try:
                # Translate rule to DSL
                base_query = sigma_service.translate_rule(rule.yaml_content)

                # Add time filter
                query = self.build_time_filtered_query(base_query, last_poll, now)

                # Execute search with retry
                response = self._execute_search_with_retry(
                    index_pattern.pattern, query, str(rule.id)
                )

                hits = response.get("hits", {}).get("hits", [])
                total_hits = response.get("hits", {}).get("total", {})
                if isinstance(total_hits, dict):
                    events_count = total_hits.get("value", 0)
                else:
                    events_count = total_hits
                total_events_scanned += events_count

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

        duration_ms = int((time.monotonic() - start_time) * 1000)

        return {
            "matches": total_matches,
            "errors": errors,
            "events_scanned": total_events_scanned,
            "duration_ms": duration_ms,
        }


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
            # Load pull mode settings from database
            pull_settings = await get_pull_mode_settings(session)
            failures_warning = pull_settings["consecutive_failures_warning"]
            failures_critical = pull_settings["consecutive_failures_critical"]

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

            # Execute poll with configurable settings
            client = get_opensearch_client()
            detector = PullDetector(client=client, settings=pull_settings)
            sigma_service = SigmaService()
            alert_service = AlertService(client=client)

            poll_result = await detector.poll_index_pattern(
                index_pattern=index_pattern,
                rules=rules,
                sigma_service=sigma_service,
                alert_service=alert_service,
                last_poll=last_poll,
            )

            # Update poll state with metrics
            now = datetime.now(timezone.utc)
            has_errors = len(poll_result["errors"]) > 0
            is_success = not has_errors

            if index_pattern.poll_state:
                ps = index_pattern.poll_state
                ps.last_poll_at = now
                ps.last_poll_status = "error" if has_errors else "success"
                ps.last_error = str(poll_result["errors"]) if has_errors else None
                ps.updated_at = now

                # Update metrics
                ps.total_polls += 1
                if is_success:
                    ps.successful_polls += 1
                    ps.consecutive_failures = 0
                else:
                    ps.failed_polls += 1
                    ps.consecutive_failures += 1

                    # Log warning/critical based on configurable thresholds
                    if ps.consecutive_failures >= failures_critical:
                        logger.error(
                            f"CRITICAL: {ps.consecutive_failures} consecutive poll failures for {index_pattern.pattern}"
                        )
                    elif ps.consecutive_failures >= failures_warning:
                        logger.warning(
                            f"WARNING: {ps.consecutive_failures} consecutive poll failures for {index_pattern.pattern}"
                        )

                ps.total_matches += poll_result["matches"]
                ps.total_events_scanned += poll_result["events_scanned"]
                ps.last_poll_duration_ms = poll_result["duration_ms"]

                # Calculate running average
                if ps.avg_poll_duration_ms is None:
                    ps.avg_poll_duration_ms = float(poll_result["duration_ms"])
                else:
                    # Exponential moving average (weight new value at 20%)
                    ps.avg_poll_duration_ms = (
                        0.8 * ps.avg_poll_duration_ms + 0.2 * poll_result["duration_ms"]
                    )
            else:
                poll_state = IndexPatternPollState(
                    index_pattern_id=index_pattern.id,
                    last_poll_at=now,
                    last_poll_status="error" if has_errors else "success",
                    last_error=str(poll_result["errors"]) if has_errors else None,
                    total_polls=1,
                    successful_polls=1 if is_success else 0,
                    failed_polls=0 if is_success else 1,
                    consecutive_failures=0 if is_success else 1,
                    total_matches=poll_result["matches"],
                    total_events_scanned=poll_result["events_scanned"],
                    last_poll_duration_ms=poll_result["duration_ms"],
                    avg_poll_duration_ms=float(poll_result["duration_ms"]),
                )
                session.add(poll_state)

            await session.commit()

            logger.info(
                f"Poll complete for {index_pattern.pattern}: "
                f"{poll_result['matches']} matches, {poll_result['events_scanned']} events scanned, "
                f"{poll_result['duration_ms']}ms, {len(poll_result['errors'])} errors"
            )

        except Exception as e:
            logger.error(f"Poll job failed for {index_pattern_id}: {e}")
            # Try to update failure count even on exception
            try:
                result = await session.execute(
                    select(IndexPattern)
                    .where(IndexPattern.id == index_pattern_id)
                    .options(selectinload(IndexPattern.poll_state))
                )
                pattern = result.scalar_one_or_none()
                if pattern and pattern.poll_state:
                    pattern.poll_state.failed_polls += 1
                    pattern.poll_state.consecutive_failures += 1
                    pattern.poll_state.last_poll_status = "error"
                    pattern.poll_state.last_error = str(e)
                    pattern.poll_state.updated_at = datetime.now(timezone.utc)
                    await session.commit()
            except Exception as update_error:
                logger.error(f"Failed to update poll state on error: {update_error}")
            raise
