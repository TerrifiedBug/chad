"""
Unified scheduler service for background sync jobs.

Uses APScheduler to manage scheduled tasks for:
- ATT&CK data sync
- SigmaHQ repository sync
- Health monitoring checks

With multiple uvicorn workers, distributed locking via Redis ensures
only one worker executes each scheduled job.
"""

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings as app_settings
from app.core.encryption import decrypt
from app.core.redis import get_redis
from app.models.setting import Setting
from app.services.system_log import LogCategory, system_log_service

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler = AsyncIOScheduler()


# Frequency to cron trigger mapping
FREQUENCY_CRON_MAP = {
    "daily": CronTrigger(hour=2, minute=0),  # 2:00 AM daily
    "weekly": CronTrigger(day_of_week=0, hour=2, minute=0),  # Sunday 2:00 AM
    "monthly": CronTrigger(day=1, hour=2, minute=0),  # 1st of month 2:00 AM
}


class SchedulerService:
    """Service for managing scheduled background jobs."""

    def __init__(self):
        self._engine = None
        self._session_factory = None

    def _get_engine(self):
        """Lazy initialization of database engine."""
        if self._engine is None:
            self._engine = create_async_engine(app_settings.DATABASE_URL)
            self._session_factory = async_sessionmaker(self._engine, class_=AsyncSession, expire_on_commit=False)
        return self._engine

    async def _get_session(self) -> AsyncSession:
        """Get a new database session."""
        self._get_engine()
        return self._session_factory()

    def start(self):
        """Start the scheduler."""
        if not scheduler.running:
            scheduler.start()
            logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler."""
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

    async def _run_with_lock(self, lock_name: str, timeout: int, job_func):
        """
        Execute a job function with distributed locking.

        Only one worker will execute the job; others will skip.

        Args:
            lock_name: Unique name for the lock (e.g., "scheduler:health_check")
            timeout: Lock timeout in seconds
            job_func: Async function to execute if lock acquired
        """
        try:
            redis = await get_redis()
        except Exception as e:
            logger.warning("Redis unavailable, running job without lock: %s", e)
            await job_func()
            return

        lock = redis.lock(lock_name, timeout=timeout, blocking=False)

        try:
            acquired = await lock.acquire(blocking=False)
            if not acquired:
                logger.debug("Lock %s held by another worker, skipping", lock_name)
                return

            try:
                await job_func()
            finally:
                try:
                    await lock.release()
                except Exception:
                    pass  # Lock may have expired
        except Exception as e:
            logger.error("Error in locked job %s: %s", lock_name, e)

    async def sync_jobs_from_settings(self):
        """
        Load job configurations from settings and schedule/reschedule jobs.

        Called on startup and when settings change.
        """
        session = await self._get_session()
        try:
            # Load settings
            result = await session.execute(
                select(Setting).where(
                    Setting.key.in_(
                        [
                            "attack_sync",
                            "sigmahq_sync",
                        ]
                    )
                )
            )
            settings = {s.key: s.value for s in result.scalars()}

            # Configure ATT&CK sync job
            attack_settings = settings.get("attack_sync", {})
            if attack_settings.get("enabled"):
                frequency = attack_settings.get("frequency", "weekly")
                self._schedule_job(
                    job_id="attack_sync",
                    func=self._run_attack_sync,
                    frequency=frequency,
                )
            else:
                self._remove_job("attack_sync")

            # Configure SigmaHQ sync job
            sigmahq_settings = settings.get("sigmahq_sync", {})
            if sigmahq_settings.get("enabled"):
                # Convert interval_hours to frequency
                interval = sigmahq_settings.get("interval_hours", 24)
                if interval <= 24:
                    frequency = "daily"
                elif interval <= 168:
                    frequency = "weekly"
                else:
                    frequency = "monthly"

                self._schedule_job(
                    job_id="sigmahq_sync",
                    func=self._run_sigmahq_sync,
                    frequency=frequency,
                )
            else:
                self._remove_job("sigmahq_sync")

            # Configure GeoIP update job
            await self._configure_geoip_job(session)

            # Configure AI connectivity ping job (hourly if AI enabled)
            await self._configure_ai_ping_job(session)

            # Add health check job (runs every minute)
            self._schedule_health_check()

            # Add correlation state cleanup job (runs every 5 minutes)
            self._schedule_correlation_cleanup()

            # Add version cleanup job (runs daily at 3 AM)
            self._schedule_version_cleanup()

            # Add system log cleanup job (runs daily at 3 AM)
            self._schedule_system_log_cleanup()

            # Add version check job (runs daily at 4 AM)
            self._schedule_version_check()

            # Schedule pull polling jobs for pull-mode index patterns
            await self._schedule_pull_polling_jobs(session)

            logger.info("Scheduler jobs synced from settings")

        finally:
            await session.close()

    def _schedule_health_check(self):
        """Schedule the health monitoring job."""
        scheduler.add_job(
            self._run_health_check,
            trigger=IntervalTrigger(minutes=1),
            id="health_check",
            name="health_check monitoring",
            replace_existing=True,
            misfire_grace_time=60,  # 1 minute grace period
        )
        logger.info("Scheduled health_check job (every 1 minute)")

    def _schedule_correlation_cleanup(self):
        """Schedule the correlation state cleanup job."""
        scheduler.add_job(
            self._run_correlation_cleanup,
            trigger=IntervalTrigger(minutes=5),
            id="correlation_cleanup",
            name="correlation state cleanup",
            replace_existing=True,
            misfire_grace_time=300,  # 5 minute grace period
        )
        logger.info("Scheduled correlation_cleanup job (every 5 minutes)")

    def _schedule_version_cleanup(self):
        """Schedule the version cleanup job (daily at 3 AM)."""
        scheduler.add_job(
            self._run_version_cleanup,
            trigger=CronTrigger(hour=3, minute=0),
            id="version_cleanup",
            name="version cleanup",
            replace_existing=True,
            misfire_grace_time=3600,  # 1 hour grace period
        )
        logger.info("Scheduled version_cleanup job (daily at 3:00 AM)")

    async def _schedule_pull_polling_jobs(self, session: AsyncSession):
        """Schedule polling jobs for pull-mode index patterns."""
        from app.models.index_pattern import IndexPattern
        from app.services.pull_detector import run_poll_job

        # Get index patterns that need polling based on deployment mode
        logger.debug("Scheduling pull polling jobs (is_pull_only=%s)", app_settings.is_pull_only)
        if app_settings.is_pull_only:
            # In pull-only mode, schedule ALL patterns for polling
            result = await session.execute(select(IndexPattern))
        else:
            # In full mode, only schedule patterns explicitly set to pull mode
            result = await session.execute(
                select(IndexPattern).where(IndexPattern.mode == "pull")
            )
        patterns = result.scalars().all()

        logger.info("Found %s index pattern(s) for pull mode polling", len(patterns))
        for pattern in patterns:
            logger.debug("Processing pattern: %s (mode=%s, interval=%smin)", pattern.name, pattern.mode, pattern.poll_interval_minutes)

            job_id = f"pull_poll_{pattern.id}"

            # Remove existing job if any
            try:
                scheduler.remove_job(job_id)
            except Exception:
                pass

            # Add new job with pattern's poll interval
            scheduler.add_job(
                run_poll_job,
                trigger=IntervalTrigger(minutes=pattern.poll_interval_minutes),
                id=job_id,
                name=f"pull_poll for {pattern.pattern}",
                args=[str(pattern.id)],
                replace_existing=True,
                misfire_grace_time=pattern.poll_interval_minutes * 60,
            )
            logger.info(
                f"Scheduled pull polling job for {pattern.pattern} "
                f"every {pattern.poll_interval_minutes} minutes"
            )

    def schedule_pull_poll_job(self, index_pattern_id: str, pattern_name: str, poll_interval_minutes: int):
        """
        Schedule or update a pull poll job for an index pattern.

        Called when a pull mode index pattern is created or updated.
        """
        from app.services.pull_detector import run_poll_job

        job_id = f"pull_poll_{index_pattern_id}"

        # Remove existing job if any
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass

        # Add new job
        scheduler.add_job(
            run_poll_job,
            trigger=IntervalTrigger(minutes=poll_interval_minutes),
            id=job_id,
            name=f"pull_poll for {pattern_name}",
            args=[index_pattern_id],
            replace_existing=True,
            misfire_grace_time=poll_interval_minutes * 60,
        )
        logger.info("Scheduled pull polling job for %s every %s minutes", pattern_name, poll_interval_minutes)

    def remove_pull_poll_job(self, index_pattern_id: str):
        """
        Remove a pull poll job for an index pattern.

        Called when an index pattern is deleted or changes from pull to push mode.
        """
        job_id = f"pull_poll_{index_pattern_id}"
        try:
            scheduler.remove_job(job_id)
            logger.info("Removed pull poll job %s", job_id)
        except Exception:
            pass  # Job didn't exist

    def _schedule_job(self, job_id: str, func, frequency: str):
        """Schedule or reschedule a job."""
        trigger = FREQUENCY_CRON_MAP.get(frequency, FREQUENCY_CRON_MAP["weekly"])

        # Remove existing job if any
        self._remove_job(job_id)

        # Add new job
        scheduler.add_job(
            func,
            trigger=trigger,
            id=job_id,
            name=f"{job_id} scheduled sync",
            replace_existing=True,
            misfire_grace_time=3600,  # 1 hour grace period
        )
        logger.info("Scheduled job %s with frequency %s", job_id, frequency)

    def _remove_job(self, job_id: str):
        """Remove a scheduled job if it exists."""
        try:
            scheduler.remove_job(job_id)
            logger.info("Removed job %s", job_id)
        except Exception:
            pass  # Job didn't exist

    async def _run_attack_sync(self):
        """Execute ATT&CK sync job with distributed lock."""
        await self._run_with_lock(
            "scheduler:attack_sync",
            timeout=3600,  # 1 hour
            job_func=self._execute_attack_sync
        )

    async def _execute_attack_sync(self):
        """Actual ATT&CK sync execution."""
        from app.services.attack_sync import attack_sync_service
        from app.services.audit import audit_log
        from app.services.notification import send_system_notification

        logger.info("Running scheduled ATT&CK sync")
        session = await self._get_session()
        try:
            result = await attack_sync_service.sync(session)

            # Update last sync time
            setting_result = await session.execute(select(Setting).where(Setting.key == "attack_sync"))
            setting = setting_result.scalar_one_or_none()
            if setting:
                setting.value = {**setting.value, "last_sync": datetime.now(UTC).isoformat()}
                await session.commit()

            # Log to audit
            await audit_log(
                session,
                None,
                "attack.sync.scheduled",
                "system",
                None,
                {"success": result.success, "techniques_updated": result.techniques_updated},
            )
            await session.commit()

            if result.success:
                # Send sync completion notification
                await send_system_notification(
                    session,
                    "attack_sync_complete",
                    {
                        "techniques_updated": result.techniques_updated,
                        "new_techniques": result.new_techniques,
                        "message": result.message,
                    },
                )
            else:
                # Send sync failure notification
                await send_system_notification(
                    session,
                    "sync_failed",
                    {
                        "sync_type": "attack",
                        "error": result.error or result.message,
                    },
                )

            logger.info("ATT&CK sync completed: %s", result.message)

        except Exception as e:
            logger.error("Scheduled ATT&CK sync failed: %s", e)
            # Log to system log
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="attack_sync",
                message=f"Scheduled ATT&CK sync failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            # Send sync failure notification
            try:
                await send_system_notification(
                    session,
                    "sync_failed",
                    {"sync_type": "attack", "error": str(e)},
                )
            except Exception:
                pass  # Don't fail on notification errors
        finally:
            await session.close()

    async def _run_sigmahq_sync(self):
        """Execute SigmaHQ sync job with distributed lock."""
        await self._run_with_lock(
            "scheduler:sigmahq_sync",
            timeout=3600,  # 1 hour
            job_func=self._execute_sigmahq_sync
        )

    async def _execute_sigmahq_sync(self):
        """Actual SigmaHQ sync execution."""
        from app.services.audit import audit_log
        from app.services.notification import send_system_notification
        from app.services.sigmahq import sigmahq_service

        logger.info("Running scheduled SigmaHQ sync")
        session = await self._get_session()
        try:
            if sigmahq_service.is_repo_cloned():
                result = sigmahq_service.pull_repo()
            else:
                result = sigmahq_service.clone_repo()

            # Update last sync time
            setting_result = await session.execute(select(Setting).where(Setting.key == "sigmahq_sync"))
            setting = setting_result.scalar_one_or_none()
            if setting:
                setting.value = {**setting.value, "last_sync": datetime.now(UTC).isoformat()}
                await session.commit()

            # Log to audit
            await audit_log(
                session,
                None,
                "sigmahq.sync.scheduled",
                "system",
                None,
                {"success": result.success, "rule_counts": result.rule_counts},
            )
            await session.commit()

            if result.success:
                # Send sync completion notification
                await send_system_notification(
                    session,
                    "sigmahq_sync_complete",
                    {
                        "rule_counts": result.rule_counts,
                        "message": result.message,
                    },
                )

                # Send new rules notification if there are new rules
                if hasattr(result, "new_rules") and result.new_rules > 0:
                    await send_system_notification(
                        session,
                        "sigmahq_new_rules",
                        {
                            "count": result.new_rules,
                            "source": "sigmahq",
                        },
                    )
            else:
                # Send sync failure notification
                await send_system_notification(
                    session,
                    "sync_failed",
                    {
                        "sync_type": "sigmahq",
                        "error": result.error if hasattr(result, "error") else result.message,
                    },
                )

            logger.info("SigmaHQ sync completed: %s", result.message)

        except Exception as e:
            logger.error("Scheduled SigmaHQ sync failed: %s", e)
            # Log to system log
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="sigmahq_sync",
                message=f"Scheduled SigmaHQ sync failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            # Send sync failure notification
            try:
                await send_system_notification(
                    session,
                    "sync_failed",
                    {"sync_type": "sigmahq", "error": str(e)},
                )
            except Exception:
                pass  # Don't fail on notification errors
        finally:
            await session.close()

    async def _run_health_check(self):
        """Execute health monitoring check with distributed lock."""
        await self._run_health_check_with_lock()

    async def _run_health_check_with_lock(self):
        """Health check wrapper with distributed locking."""
        await self._run_with_lock(
            "scheduler:health_check",
            timeout=30,
            job_func=self._execute_health_check
        )

    async def _execute_health_check(self):
        """Actual health check execution (extracted for testability)."""
        from app.background.tasks.health_checks import (
            check_jira_health,
            check_opensearch_health,
            check_ti_source_health,
        )
        from app.services.health_monitor import check_index_health

        logger.debug("Running scheduled health check")
        session = await self._get_session()
        try:
            # Check index health (updates suppression state in DB)
            issues = await check_index_health(session)
            # Commit suppression state changes so escalation persists between runs
            await session.commit()
            if issues:
                logger.info("Health check found %s issues", len(issues))

            # Check OpenSearch connectivity
            try:
                await check_opensearch_health(session)
                logger.debug("OpenSearch health check completed")
            except Exception as e:
                logger.error("OpenSearch health check failed: %s", e)

            # Check Jira connectivity
            try:
                await check_jira_health(session)
                logger.debug("Jira health check completed")
            except Exception as e:
                logger.error("Jira health check failed: %s", e)

            # Check AI connectivity (free endpoints, no token cost)
            try:
                await self._run_ai_ping()
                logger.debug("AI health check completed")
            except Exception as e:
                logger.error("AI health check failed: %s", e)

            # Check TI sources connectivity
            try:
                await check_ti_source_health(session)
                logger.debug("TI source health check completed")
            except Exception as e:
                logger.error("TI source health check failed: %s", e)

        except Exception as e:
            logger.error("Scheduled health check failed: %s", e)
            await session.rollback()
        finally:
            await session.close()

    async def _configure_ai_ping_job(self, session: AsyncSession):
        """
        AI connectivity ping is now part of the main health check that runs every minute.
        This method is kept for compatibility but no longer schedules a separate job.
        """
        # AI health checks are now run every minute in _run_health_check()
        # Remove any old hourly job if it exists
        self._remove_job("ai_ping")
        logger.debug("AI health checks now run every minute via main health check")

    async def _run_ai_ping(self):
        """Execute AI connectivity ping (lightweight, no token consumption)."""
        import httpx

        logger.debug("Running scheduled AI connectivity ping")
        session = await self._get_session()
        try:
            result = await session.execute(select(Setting).where(Setting.key == "ai"))
            setting = result.scalar_one_or_none()
            if not setting:
                return

            ai_settings = setting.value or {}
            provider = ai_settings.get("ai_provider", "disabled")

            if provider == "disabled":
                return

            success = False
            async with httpx.AsyncClient(timeout=10.0) as client:
                if provider == "ollama":
                    url = ai_settings.get("ai_ollama_url", "http://localhost:11434")
                    response = await client.get(f"{url.rstrip('/')}/api/tags")
                    success = response.status_code == 200

                elif provider == "openai":
                    api_key = ai_settings.get("ai_openai_key", "")
                    if api_key:
                        try:
                            api_key = decrypt(api_key)
                            response = await client.get(
                                "https://api.openai.com/v1/models",
                                headers={"Authorization": f"Bearer {api_key}"},
                            )
                            success = response.status_code == 200
                        except Exception:
                            success = False

                elif provider == "anthropic":
                    # Use /v1/models endpoint - free, no token consumption
                    api_key = ai_settings.get("ai_anthropic_key", "")
                    if api_key:
                        try:
                            api_key = decrypt(api_key)
                            response = await client.get(
                                "https://api.anthropic.com/v1/models",
                                headers={
                                    "x-api-key": api_key,
                                    "anthropic-version": "2023-06-01",
                                },
                            )
                            success = response.status_code == 200
                        except Exception:
                            success = False

            # Update status
            ai_settings["last_tested"] = datetime.now(UTC).isoformat()
            ai_settings["last_test_success"] = success
            setting.value = ai_settings
            await session.commit()

            if success:
                logger.debug("AI connectivity ping successful for %s", provider)
            else:
                logger.warning("AI connectivity ping failed for %s", provider)

        except Exception as e:
            logger.error("AI connectivity ping failed: %s", e)
        finally:
            await session.close()

    async def _configure_geoip_job(self, session: AsyncSession):
        """Configure the GeoIP database update job."""
        # Load GeoIP settings
        result = await session.execute(
            select(Setting).where(Setting.key.in_(["geoip_enabled", "geoip_update_interval", "geoip_license_key"]))
        )
        geoip_settings = {s.key: s.value for s in result.scalars()}

        enabled = geoip_settings.get("geoip_enabled", False)
        has_license = bool(geoip_settings.get("geoip_license_key"))

        if enabled and has_license:
            update_interval = geoip_settings.get("geoip_update_interval", "weekly")
            self._schedule_job(
                job_id="geoip_update",
                func=self._run_geoip_update,
                frequency=update_interval,
            )
        else:
            self._remove_job("geoip_update")

    async def _run_geoip_update(self):
        """Execute GeoIP database update job with distributed lock."""
        await self._run_with_lock(
            "scheduler:geoip_update",
            timeout=600,  # 10 minutes
            job_func=self._execute_geoip_update
        )

    async def _execute_geoip_update(self):
        """Actual GeoIP database update execution."""
        from app.services.geoip import geoip_service

        logger.info("Running scheduled GeoIP database update")
        session = await self._get_session()
        try:
            # Check if enabled and has license key
            result = await session.execute(
                select(Setting).where(Setting.key.in_(["geoip_enabled", "geoip_license_key", "geoip_last_update"]))
            )
            settings = {s.key: s.value for s in result.scalars()}

            if not settings.get("geoip_enabled"):
                logger.debug("GeoIP not enabled, skipping update")
                return

            license_key = settings.get("geoip_license_key")
            if not license_key:
                logger.debug("No GeoIP license key configured, skipping update")
                return

            # Download/update the database
            decrypted_key = decrypt(license_key)
            result = await geoip_service.download_database(decrypted_key)

            if result["success"]:
                # Update last update timestamp
                last_update_setting = await session.execute(
                    select(Setting).where(Setting.key == "geoip_last_update")
                )
                setting = last_update_setting.scalar_one_or_none()
                if setting:
                    setting.value = datetime.now(UTC).isoformat()
                else:
                    session.add(Setting(key="geoip_last_update", value=datetime.now(UTC).isoformat()))
                await session.commit()
                logger.info("GeoIP database updated successfully")
            else:
                logger.error("GeoIP database update failed: %s", result.get('error'))

        except Exception as e:
            logger.error("Scheduled GeoIP update failed: %s", e)
            # Log to system log
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="geoip_update",
                message=f"Scheduled GeoIP update failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
        finally:
            await session.close()

    def get_next_run_time(self, job_id: str) -> datetime | None:
        """Get the next scheduled run time for a job."""
        job = scheduler.get_job(job_id)
        if job:
            return job.next_run_time
        return None

    async def _run_correlation_cleanup(self):
        """Execute correlation state cleanup job with distributed lock."""
        await self._run_with_lock(
            "scheduler:correlation_cleanup",
            timeout=300,  # 5 minutes
            job_func=self._execute_correlation_cleanup
        )

    async def _execute_correlation_cleanup(self):
        """Actual correlation state cleanup execution."""
        from app.services.correlation import cleanup_expired_states

        logger.debug("Running scheduled correlation state cleanup")
        session = await self._get_session()
        try:
            count = await cleanup_expired_states(session)
            await session.commit()
            if count > 0:
                logger.info("Correlation cleanup: removed %s expired states", count)
        except Exception as e:
            logger.error("Scheduled correlation cleanup failed: %s", e)
            # Log to system log
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="correlation_cleanup",
                message=f"Scheduled correlation cleanup failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
        finally:
            await session.close()

    async def _run_version_cleanup(self):
        """Execute version cleanup job with distributed lock."""
        await self._run_with_lock(
            "scheduler:version_cleanup",
            timeout=1800,  # 30 minutes
            job_func=self._execute_version_cleanup
        )

    async def _execute_version_cleanup(self):
        """
        Actual version cleanup execution.

        Deletes old rule and correlation rule versions based on settings:
        - version_cleanup_enabled: Whether cleanup is enabled (default: True)
        - version_cleanup_min_keep: Minimum versions to always keep (default: 10)
        - version_cleanup_max_age_days: Max age in days for versions beyond min_keep (default: 90)
        """
        from datetime import timedelta

        from sqlalchemy import and_, delete, func

        from app.models.correlation_rule import CorrelationRuleVersion
        from app.models.rule import RuleVersion
        from app.services.settings import get_setting

        logger.info("Running scheduled version cleanup")
        session = await self._get_session()
        try:
            # Get cleanup settings
            cleanup_settings = await get_setting(session, "version_cleanup") or {}
            if not cleanup_settings.get("enabled", True):
                logger.debug("Version cleanup is disabled")
                return

            min_keep = cleanup_settings.get("min_keep", 10)
            max_age_days = cleanup_settings.get("max_age_days", 90)
            cutoff_date = datetime.now(UTC) - timedelta(days=max_age_days)

            total_deleted = 0

            # Clean up rule versions
            # For each rule, get versions to delete (beyond min_keep AND older than cutoff)
            # This is done per-rule to ensure we always keep min_keep versions
            from app.models.rule import Rule
            rule_result = await session.execute(select(Rule.id))
            rule_ids = [r[0] for r in rule_result.fetchall()]

            for rule_id in rule_ids:
                # Get version count for this rule
                count_result = await session.execute(
                    select(func.count()).select_from(RuleVersion).where(RuleVersion.rule_id == rule_id)
                )
                version_count = count_result.scalar()

                if version_count <= min_keep:
                    continue  # Don't delete if at or below minimum

                # Get the version_number of the min_keep-th newest version
                threshold_result = await session.execute(
                    select(RuleVersion.version_number)
                    .where(RuleVersion.rule_id == rule_id)
                    .order_by(RuleVersion.version_number.desc())
                    .offset(min_keep - 1)
                    .limit(1)
                )
                threshold_version = threshold_result.scalar()
                if threshold_version is None:
                    continue

                # Delete versions older than threshold AND older than cutoff date
                delete_result = await session.execute(
                    delete(RuleVersion).where(
                        and_(
                            RuleVersion.rule_id == rule_id,
                            RuleVersion.version_number < threshold_version,
                            RuleVersion.created_at < cutoff_date
                        )
                    )
                )
                total_deleted += delete_result.rowcount

            # Clean up correlation rule versions (same logic)
            from app.models.correlation_rule import CorrelationRule
            corr_result = await session.execute(select(CorrelationRule.id))
            corr_ids = [r[0] for r in corr_result.fetchall()]

            for corr_id in corr_ids:
                count_result = await session.execute(
                    select(func.count()).select_from(CorrelationRuleVersion).where(
                        CorrelationRuleVersion.correlation_rule_id == corr_id
                    )
                )
                version_count = count_result.scalar()

                if version_count <= min_keep:
                    continue

                threshold_result = await session.execute(
                    select(CorrelationRuleVersion.version_number)
                    .where(CorrelationRuleVersion.correlation_rule_id == corr_id)
                    .order_by(CorrelationRuleVersion.version_number.desc())
                    .offset(min_keep - 1)
                    .limit(1)
                )
                threshold_version = threshold_result.scalar()
                if threshold_version is None:
                    continue

                delete_result = await session.execute(
                    delete(CorrelationRuleVersion).where(
                        and_(
                            CorrelationRuleVersion.correlation_rule_id == corr_id,
                            CorrelationRuleVersion.version_number < threshold_version,
                            CorrelationRuleVersion.created_at < cutoff_date
                        )
                    )
                )
                total_deleted += delete_result.rowcount

            await session.commit()

            if total_deleted > 0:
                logger.info("Version cleanup: deleted %s old versions", total_deleted)
                # Audit log
                from app.services.audit import audit_log
                await audit_log(
                    session,
                    None,
                    "system.version_cleanup",
                    "system",
                    None,
                    {"versions_deleted": total_deleted, "min_keep": min_keep, "max_age_days": max_age_days}
                )
                await session.commit()
            else:
                logger.debug("Version cleanup: no versions to delete")

        except Exception as e:
            logger.error("Scheduled version cleanup failed: %s", e)
            # Log to system log
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="version_cleanup",
                message=f"Scheduled version cleanup failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            await session.rollback()
        finally:
            await session.close()

    def _schedule_system_log_cleanup(self):
        """Schedule the system log cleanup job (daily at 3 AM)."""
        scheduler.add_job(
            self._run_system_log_cleanup,
            trigger=CronTrigger(hour=3, minute=0),
            id="system_log_cleanup",
            name="system log cleanup",
            replace_existing=True,
            misfire_grace_time=3600,  # 1 hour grace period
        )
        logger.info("Scheduled system_log_cleanup job (daily at 3:00 AM)")

    async def _run_system_log_cleanup(self):
        """Execute system log cleanup job with distributed lock."""
        await self._run_with_lock(
            "scheduler:system_log_cleanup",
            timeout=300,  # 5 minutes
            job_func=self._execute_system_log_cleanup
        )

    async def _execute_system_log_cleanup(self):
        """Purge old system logs based on retention setting."""
        from app.services.settings import get_setting
        from app.services.system_log import system_log_service

        logger.debug("Running scheduled system log cleanup")
        session = await self._get_session()
        try:
            # Get retention days from settings (default 14)
            retention_setting = await get_setting(session, "system_log_retention_days")
            retention_days = int(retention_setting) if retention_setting else 14

            deleted = await system_log_service.purge_old_logs(session, retention_days=retention_days)
            await session.commit()  # Commit since purge_old_logs doesn't commit

            if deleted > 0:
                logger.info("System log cleanup: purged %s entries older than %s days", deleted, retention_days)
            else:
                logger.debug("System log cleanup: no entries to purge")

        except Exception as e:
            logger.error("Scheduled system log cleanup failed: %s", e)
            # Log to system log (using a fresh session to avoid rollback issues)
            try:
                await system_log_service.log_error(
                    session,
                    category=LogCategory.BACKGROUND,
                    service="system_log_cleanup",
                    message=f"Scheduled system log cleanup failed: {str(e)}",
                    details={"error": str(e), "error_type": type(e).__name__}
                )
            except Exception:
                pass  # Avoid recursive issues if logging itself fails
            await session.rollback()
        finally:
            await session.close()

    def _schedule_version_check(self):
        """Schedule the version check job (daily at 4 AM)."""
        scheduler.add_job(
            self._run_version_check,
            trigger=CronTrigger(hour=4, minute=0),
            id="version_check",
            name="version check",
            replace_existing=True,
            misfire_grace_time=3600,  # 1 hour grace period
        )
        logger.info("Scheduled version_check job (daily at 4:00 AM)")

    async def _run_version_check(self):
        """Execute version check job with distributed lock."""
        await self._run_with_lock(
            "scheduler:version_check",
            timeout=60,  # 1 minute
            job_func=self._execute_version_check
        )

    async def _execute_version_check(self):
        """Check GitHub for latest version and cache result."""
        import httpx

        from app.core.config import APP_VERSION
        from app.services.settings import set_setting

        logger.debug("Running scheduled version check")
        session = await self._get_session()
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/repos/TerrifiedBug/chad/releases/latest",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    latest = data.get("tag_name", "").lstrip("v")
                    # Simple version comparison
                    update_available = False
                    if latest and latest != APP_VERSION:
                        try:
                            current_parts = [int(x) for x in APP_VERSION.split("-")[0].split(".")]
                            latest_parts = [int(x) for x in latest.split("-")[0].split(".")]
                            while len(current_parts) < 3:
                                current_parts.append(0)
                            while len(latest_parts) < 3:
                                latest_parts.append(0)
                            update_available = latest_parts > current_parts
                        except (ValueError, AttributeError):
                            # We're inside `if latest != APP_VERSION`, so update is available
                            update_available = True

                    # Cache the result
                    await set_setting(session, "version_check_cache", {
                        "latest": latest,
                        "update_available": update_available,
                        "release_url": data.get("html_url"),
                        "checked_at": datetime.now(UTC).isoformat(),
                    })
                    await session.commit()
                    logger.info(
                        "Version check: current=%s, latest=%s, update=%s",
                        APP_VERSION, latest, update_available
                    )
                else:
                    logger.warning("Version check failed: GitHub returned %s", response.status_code)

        except Exception as e:
            logger.error("Scheduled version check failed: %s", e)
            await system_log_service.log_error(
                session,
                category=LogCategory.BACKGROUND,
                service="version_check",
                message=f"Scheduled version check failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__}
            )
            await session.rollback()
        finally:
            await session.close()

    async def update_health_check_intervals(self, intervals: dict):
        """
        Update health check intervals.

        Note: The current implementation runs all health checks every minute.
        The intervals are stored in settings and will be used by future
        optimizations to run each service check at its configured interval.

        For now, this just stores the configuration for reference.
        """
        session = await self._get_session()
        try:
            from app.services.settings import set_setting
            await set_setting(session, "health_check_intervals", intervals)
            await session.commit()
            logger.info("Health check intervals updated: %s", intervals)
        except Exception as e:
            logger.error("Failed to update health check intervals: %s", e)
            await session.rollback()
            raise
        finally:
            await session.close()


# Singleton instance
scheduler_service = SchedulerService()
