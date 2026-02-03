"""Pull-based detection service for querying OpenSearch on schedule."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import yaml
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule_exception import RuleException
from app.services.alert_pubsub import publish_alert
from app.services.alerts import AlertService, should_suppress_alert
from app.services.correlation import check_correlation
from app.services.enrichment import enrich_alert
from app.services.notification import send_alert_notification
from app.services.settings import get_app_url
from app.services.system_log import LogCategory, system_log_service

logger = logging.getLogger(__name__)

# Default constants for retry logic (used when settings not loaded)
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY_SECONDS = 5
DEFAULT_CONSECUTIVE_FAILURES_WARNING = 3
DEFAULT_CONSECUTIVE_FAILURES_CRITICAL = 10

# Pagination settings
BATCH_SIZE = 1000  # Events per batch
MAX_EVENTS_PER_POLL = 100000  # Safety limit to prevent runaway queries


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
            logger.debug(f"Failed to load exceptions for rule {rule_id}: {e}")
            cache[rule_id] = []

        return cache[rule_id]

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
                logger.warning(f"Failed to broadcast alert {alert.get('alert_id')}: {e}")

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
                logger.warning(f"Failed to send notification for alert {alert['alert_id']}: {e}")

    async def _check_correlations(
        self,
        db: AsyncSession,
        rule_id: str,
        enriched_log: dict,
        alert: dict,
        alerts_index: str,
        alert_service: AlertService,
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
                # Gather tags from both rules for the correlation alert
                correlation_tags = []
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
                correlation_alert = alert_service.create_alert(
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
                            "rule_a_id": str(rule_a_id) if rule_a_id else None,
                            "rule_b_id": str(rule_b_id) if rule_b_id else None,
                            "entity_field": corr.get("entity_field"),
                            "entity_value": corr.get("entity_value"),
                            "time_window_minutes": corr.get("time_window_minutes"),
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
            logger.error(f"Correlation check failed: {e}")

    async def _get_rule_tags(self, db: AsyncSession, rule_id: str) -> tuple[str | None, list[str]]:
        """Get rule title and MITRE tags from a rule."""
        from app.models.rule import Rule

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
                        logger.debug("Failed to parse rule YAML for tags: %s", e)
                return title, tags
        except Exception as e:
            logger.debug("Failed to get rule info: %s", e)
        return None, []

    def build_time_filtered_query(
        self,
        base_query: dict[str, Any],
        last_poll: datetime | None,
        now: datetime,
        timestamp_field: str = "@timestamp",
        default_lookback_minutes: int = 60,
    ) -> dict[str, Any]:
        """
        Wrap the base query with a time filter.

        Args:
            base_query: The original DSL query from Sigma translation
            last_poll: Last successful poll time, or None for first poll
            now: Current time
            timestamp_field: The timestamp field name to filter on (configurable per index pattern)
            default_lookback_minutes: Minutes to look back if no last_poll (defaults to 60, but uses poll_interval_minutes when available)

        Returns:
            Query with time range filter added
        """
        # If no last poll, look back by the configured interval (or default)
        if last_poll is None:
            last_poll = now - timedelta(minutes=default_lookback_minutes)

        time_filter = {
            "range": {
                timestamp_field: {
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

    async def _execute_search_with_retry(
        self,
        index_pattern: str,
        query: dict[str, Any],
        rule_id: str,
        sort_field: str = "@timestamp",
        search_after: list | None = None,
        pit_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute OpenSearch query with retry logic (async-safe).

        Uses asyncio.to_thread() to avoid blocking the event loop.

        Args:
            index_pattern: OpenSearch index pattern
            query: DSL query to execute
            rule_id: Rule ID for logging
            sort_field: Field to sort by for pagination
            search_after: search_after values for pagination
            pit_id: Point in Time ID for consistent pagination

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
                # Build search body
                body: dict[str, Any] = {
                    "query": query,
                    "size": BATCH_SIZE,
                    "sort": [{sort_field: "asc"}, {"_id": "asc"}],  # Deterministic sort for pagination
                }

                if search_after:
                    body["search_after"] = search_after

                if pit_id:
                    body["pit"] = {"id": pit_id, "keep_alive": "2m"}
                    # When using PIT, don't specify index in the search call
                    result = await asyncio.to_thread(
                        self.client.search,
                        body=body,
                    )
                else:
                    result = await asyncio.to_thread(
                        self.client.search,
                        index=index_pattern,
                        body=body,
                    )
                return result

            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    logger.warning(
                        f"OpenSearch query failed for rule {rule_id} (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    # Use async sleep to not block the event loop
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error(
                        f"OpenSearch query failed for rule {rule_id} after {max_retries} attempts: {e}"
                    )
        raise last_error

    async def _open_pit(self, index_pattern: str) -> str | None:
        """Open a Point in Time for consistent pagination."""
        try:
            response = await asyncio.to_thread(
                self.client.create_pit,
                index=index_pattern,
                keep_alive="5m",
            )
            return response.get("pit_id")
        except Exception as e:
            logger.warning(f"Failed to open PIT for {index_pattern}, will paginate without: {e}")
            return None

    async def _close_pit(self, pit_id: str) -> None:
        """Close a Point in Time."""
        try:
            await asyncio.to_thread(
                self.client.delete_pit,
                body={"pit_id": pit_id},
            )
        except Exception as e:
            logger.debug(f"Failed to close PIT: {e}")

    async def poll_index_pattern(
        self,
        index_pattern,  # IndexPattern model
        rules: list,  # List of Rule models
        sigma_service,  # SigmaService
        alert_service,  # AlertService
        last_poll: datetime | None,
        db: AsyncSession,  # Database session for field mapping resolution
    ) -> dict[str, Any]:
        """
        Poll an index pattern for all deployed rules with full pagination support.

        Args:
            index_pattern: The IndexPattern to poll
            rules: List of deployed Rule models
            sigma_service: Service for translating Sigma to DSL
            alert_service: Service for creating alerts
            last_poll: Last successful poll time
            db: Database session for resolving field mappings

        Returns:
            Dict with poll results: {"matches": int, "errors": list, "events_scanned": int, "duration_ms": int, "truncated": bool}
        """
        import time as time_module

        from dateutil.parser import parse as parse_datetime
        start_time = time_module.monotonic()
        now = datetime.now(UTC)
        total_matches = 0
        total_events_scanned = 0
        errors = []
        truncated = False
        detection_latencies_ms: list[float] = []  # Track real detection latency per event

        # Get the configurable timestamp field (defaults to @timestamp)
        timestamp_field = getattr(index_pattern, "timestamp_field", "@timestamp") or "@timestamp"

        # Alerts index follows naming convention: chad-alerts-{index_pattern_name}
        alerts_index = f"chad-alerts-{index_pattern.name}"

        # Import here to avoid circular imports
        from app.services.field_mapping import resolve_mappings

        # Cache for rule exceptions (avoid repeated DB queries)
        rule_exceptions_cache: dict[str, list[dict]] = {}

        # Track alerts for broadcast/notification
        alerts_created: list[dict] = []
        suppressed_count = 0

        # Get app URL for notification links
        app_url = await get_app_url(db)

        for rule in rules:
            try:
                # Extract tags from Sigma YAML for alert creation
                rule_tags = []
                try:
                    parsed_rule = yaml.safe_load(rule.yaml_content)
                    if parsed_rule and isinstance(parsed_rule, dict):
                        rule_tags = parsed_rule.get("tags", []) or []
                except yaml.YAMLError:
                    logger.debug(f"Failed to parse YAML for tags in rule {rule.id}")

                # Translate rule to DSL
                result = sigma_service.translate_and_validate(rule.yaml_content)
                if not result.success:
                    errors_str = ", ".join(e.message for e in (result.errors or []))
                    errors.append({"rule_id": str(rule.id), "error": f"Translation failed: {errors_str}"})
                    continue

                # Apply field mappings if configured (matching rule_testing.py behavior)
                sigma_fields = list(result.fields or set())
                if sigma_fields and index_pattern.id:
                    field_mappings_dict = await resolve_mappings(db, sigma_fields, index_pattern.id)
                    field_mappings_dict = {k: v for k, v in field_mappings_dict.items() if v is not None}

                    if field_mappings_dict:
                        result = sigma_service.translate_with_mappings(rule.yaml_content, field_mappings_dict)
                        if not result.success:
                            errors_str = ", ".join(e.message for e in (result.errors or []))
                            errors.append({"rule_id": str(rule.id), "error": f"Translation with mappings failed: {errors_str}"})
                            continue

                # Sigma returns {"query": {"query_string": ...}}, we need just {"query_string": ...}
                base_query = result.query.get("query", result.query)

                # Add time filter using configurable timestamp field
                # Use poll_interval_minutes as the initial lookback for first poll
                query = self.build_time_filtered_query(
                    base_query, last_poll, now, timestamp_field,
                    default_lookback_minutes=index_pattern.poll_interval_minutes,
                )

                # Open PIT for consistent pagination
                pit_id = await self._open_pit(index_pattern.pattern)

                try:
                    search_after = None
                    rule_matches = 0
                    rule_events = 0

                    while True:
                        # Execute search with pagination
                        response = await self._execute_search_with_retry(
                            index_pattern.pattern,
                            query,
                            str(rule.id),
                            sort_field=timestamp_field,
                            search_after=search_after,
                            pit_id=pit_id,
                        )

                        hits = response.get("hits", {}).get("hits", [])

                        # Get total count (first page only)
                        if search_after is None:
                            total_hits = response.get("hits", {}).get("total", {})
                            if isinstance(total_hits, dict):
                                rule_events = total_hits.get("value", 0)
                            else:
                                rule_events = total_hits

                            # Warn if we're going to truncate
                            if rule_events > MAX_EVENTS_PER_POLL:
                                logger.warning(
                                    f"Rule {rule.id} matched {rule_events} events, truncating to {MAX_EVENTS_PER_POLL}"
                                )
                                truncated = True

                        if not hits:
                            break

                        # Get exceptions for this rule (cached)
                        exceptions = await self._get_rule_exceptions(db, str(rule.id), rule_exceptions_cache)

                        # Process each hit with full alert workflow
                        for hit in hits:
                            log_document = hit["_source"]

                            # Calculate real detection latency from event timestamp
                            event_timestamp_raw = log_document.get(timestamp_field) or log_document.get("@timestamp")
                            if event_timestamp_raw:
                                try:
                                    if isinstance(event_timestamp_raw, str):
                                        event_timestamp = parse_datetime(event_timestamp_raw)
                                    elif isinstance(event_timestamp_raw, datetime):
                                        event_timestamp = event_timestamp_raw
                                    else:
                                        event_timestamp = None

                                    if event_timestamp:
                                        # Ensure timezone awareness
                                        if event_timestamp.tzinfo is None:
                                            event_timestamp = event_timestamp.replace(tzinfo=UTC)
                                        latency_ms = (now - event_timestamp).total_seconds() * 1000
                                        if latency_ms >= 0:  # Sanity check (shouldn't be negative)
                                            detection_latencies_ms.append(latency_ms)
                                except Exception as e:
                                    logger.debug(f"Could not parse event timestamp for latency calc: {e}")

                            # Check if alert should be suppressed by exception
                            if should_suppress_alert(log_document, exceptions):
                                suppressed_count += 1
                                continue

                            # Enrich log with GeoIP/TI data if configured
                            try:
                                enriched_log = await enrich_alert(db, log_document, index_pattern)
                            except Exception as e:
                                logger.warning(f"Enrichment failed for log: {e}")
                                enriched_log = log_document

                            # Create individual alert
                            try:
                                alert = alert_service.create_alert(
                                    alerts_index=alerts_index,
                                    rule_id=str(rule.id),
                                    rule_title=rule.title,
                                    severity=rule.severity,
                                    tags=rule_tags,
                                    log_document=enriched_log,
                                )
                                alerts_created.append(alert)
                                rule_matches += 1

                                # Check for correlation triggers
                                await self._check_correlations(
                                    db=db,
                                    rule_id=str(rule.id),
                                    enriched_log=enriched_log,
                                    alert=alert,
                                    alerts_index=alerts_index,
                                    alert_service=alert_service,
                                    alerts_created=alerts_created,
                                )

                            except Exception as e:
                                logger.error(f"Failed to create alert for rule {rule.id}: {e}")
                                continue

                            # Safety check to prevent runaway queries
                            if rule_matches >= MAX_EVENTS_PER_POLL:
                                logger.warning(f"Reached max events limit for rule {rule.id}")
                                truncated = True
                                break

                        if rule_matches >= MAX_EVENTS_PER_POLL:
                            break

                        # Get search_after values for next page
                        if hits:
                            search_after = hits[-1].get("sort")
                            if not search_after:
                                break

                        # If we got fewer results than batch size, we're done
                        if len(hits) < BATCH_SIZE:
                            break

                    total_matches += rule_matches
                    total_events_scanned += rule_events

                finally:
                    # Always close PIT
                    if pit_id:
                        await self._close_pit(pit_id)

            except Exception as e:
                logger.error(f"Error polling rule {rule.id}: {e}")
                errors.append({"rule_id": str(rule.id), "error": str(e)})
                await system_log_service.log_error(
                    db,
                    category=LogCategory.PULL_MODE,
                    service="pull_detector",
                    message=f"Pull detection failed for rule {rule.title}",
                    details={
                        "rule_id": str(rule.id),
                        "rule_title": rule.title,
                        "index_pattern": index_pattern.pattern,
                        "error": str(e),
                        "error_type": type(e).__name__,
                    },
                )

        # Broadcast alerts via WebSocket (Redis pub/sub for cross-worker)
        if alerts_created:
            await self._broadcast_alerts(alerts_created)

        # Send notifications for created alerts
        if alerts_created:
            await self._send_notifications(db, alerts_created, app_url)

        duration_ms = int((time_module.monotonic() - start_time) * 1000)

        # Calculate average detection latency from real timestamps
        avg_detection_latency_ms = None
        if detection_latencies_ms:
            avg_detection_latency_ms = sum(detection_latencies_ms) / len(detection_latencies_ms)

        logger.info(
            f"Pull mode poll completed: {len(rules)} rules, {total_events_scanned} events, "
            f"{total_matches} matches, {len(alerts_created)} alerts, {suppressed_count} suppressed "
            f"in {duration_ms}ms (avg detection latency: {avg_detection_latency_ms:.0f}ms)" if avg_detection_latency_ms else
            f"Pull mode poll completed: {len(rules)} rules, {total_events_scanned} events, "
            f"{total_matches} matches, {len(alerts_created)} alerts, {suppressed_count} suppressed "
            f"in {duration_ms}ms"
        )

        return {
            "matches": total_matches,
            "errors": errors,
            "events_scanned": total_events_scanned,
            "duration_ms": duration_ms,
            "truncated": truncated,
            "alerts_created": len(alerts_created),
            "suppressed": suppressed_count,
            "avg_detection_latency_ms": avg_detection_latency_ms,
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

    Uses database-level locking to prevent concurrent execution by multiple workers.
    This works without Redis (for pull-only deployments).

    Args:
        index_pattern_id: UUID of the index pattern to poll
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.db.session import async_session_maker
    from app.models.index_pattern import IndexPattern
    from app.models.poll_state import IndexPatternPollState
    from app.models.rule import Rule, RuleStatus
    from app.services.alerts import AlertService
    from app.services.opensearch import get_client_from_settings
    from app.services.sigma import SigmaService

    logger.info(f"Running pull poll for index pattern {index_pattern_id}")

    async with async_session_maker() as session:
        try:
            # Load pull mode settings from database
            pull_settings = await get_pull_mode_settings(session)
            failures_warning = pull_settings["consecutive_failures_warning"]
            failures_critical = pull_settings["consecutive_failures_critical"]

            # Try to acquire lock on poll state using database-level locking
            # This prevents multiple workers from polling the same pattern simultaneously
            # Uses SKIP LOCKED to immediately return if another worker has the lock
            lock_result = await session.execute(
                select(IndexPatternPollState)
                .where(IndexPatternPollState.index_pattern_id == index_pattern_id)
                .with_for_update(skip_locked=True)
            )
            poll_state_lock = lock_result.scalar_one_or_none()

            # If poll_state doesn't exist yet, we need to check if another worker is creating it
            # by trying to lock the index_pattern row instead
            if poll_state_lock is None:
                # Check if poll_state exists but is locked
                check_result = await session.execute(
                    select(IndexPatternPollState)
                    .where(IndexPatternPollState.index_pattern_id == index_pattern_id)
                )
                existing_state = check_result.scalar_one_or_none()

                if existing_state is not None:
                    # State exists but is locked by another worker - skip this poll
                    logger.debug(f"Poll state for {index_pattern_id} is locked by another worker, skipping")
                    return
                # else: state doesn't exist, we'll create it below

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
            client = await get_client_from_settings(session)
            if not client:
                logger.error("OpenSearch client not configured")
                return

            detector = PullDetector(client=client, settings=pull_settings)
            sigma_service = SigmaService()
            alert_service = AlertService(client=client)

            poll_result = await detector.poll_index_pattern(
                index_pattern=index_pattern,
                rules=rules,
                sigma_service=sigma_service,
                alert_service=alert_service,
                last_poll=last_poll,
                db=session,
            )

            # Update poll state with metrics
            now = datetime.now(UTC)
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

                # Calculate running average for poll duration
                if ps.avg_poll_duration_ms is None:
                    ps.avg_poll_duration_ms = float(poll_result["duration_ms"])
                else:
                    # Exponential moving average (weight new value at 20%)
                    ps.avg_poll_duration_ms = (
                        0.8 * ps.avg_poll_duration_ms + 0.2 * poll_result["duration_ms"]
                    )

                # Update real detection latency if we have data
                if poll_result.get("avg_detection_latency_ms") is not None:
                    if ps.avg_detection_latency_ms is None:
                        ps.avg_detection_latency_ms = poll_result["avg_detection_latency_ms"]
                    else:
                        # Exponential moving average for detection latency
                        ps.avg_detection_latency_ms = (
                            0.8 * ps.avg_detection_latency_ms + 0.2 * poll_result["avg_detection_latency_ms"]
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
                    avg_detection_latency_ms=poll_result.get("avg_detection_latency_ms"),
                )
                session.add(poll_state)

            await session.commit()

            truncated_msg = " (TRUNCATED)" if poll_result.get("truncated") else ""
            logger.info(
                f"Poll complete for {index_pattern.pattern}: "
                f"{poll_result['matches']} matches, {poll_result['events_scanned']} events scanned, "
                f"{poll_result['duration_ms']}ms, {len(poll_result['errors'])} errors{truncated_msg}"
            )

        except Exception as e:
            logger.error(f"Poll job failed for {index_pattern_id}: {e}")
            # Log to system log service
            await system_log_service.log_error(
                session,
                category=LogCategory.PULL_MODE,
                service="pull_detector",
                message="Pull poll job failed for index pattern",
                details={
                    "index_pattern_id": index_pattern_id,
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
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
                    pattern.poll_state.updated_at = datetime.now(UTC)
                    await session.commit()
            except Exception as update_error:
                logger.error(f"Failed to update poll state on error: {update_error}")
            raise
