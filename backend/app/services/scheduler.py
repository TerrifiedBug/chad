"""
Unified scheduler service for background sync jobs.

Uses APScheduler to manage scheduled tasks for:
- ATT&CK data sync
- SigmaHQ repository sync
- Health monitoring checks
"""

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings as app_settings
from app.models.setting import Setting

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

            # Add health check job (runs every minute)
            self._schedule_health_check()

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
        logger.info(f"Scheduled job {job_id} with frequency {frequency}")

    def _remove_job(self, job_id: str):
        """Remove a scheduled job if it exists."""
        try:
            scheduler.remove_job(job_id)
            logger.info(f"Removed job {job_id}")
        except Exception:
            pass  # Job didn't exist

    async def _run_attack_sync(self):
        """Execute ATT&CK sync job."""
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
                    "sync_failure",
                    {
                        "sync_type": "attack",
                        "error": result.error or result.message,
                    },
                )

            logger.info(f"ATT&CK sync completed: {result.message}")

        except Exception as e:
            logger.error(f"Scheduled ATT&CK sync failed: {e}")
            # Send sync failure notification
            try:
                await send_system_notification(
                    session,
                    "sync_failure",
                    {"sync_type": "attack", "error": str(e)},
                )
            except Exception:
                pass  # Don't fail on notification errors
        finally:
            await session.close()

    async def _run_sigmahq_sync(self):
        """Execute SigmaHQ sync job."""
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
                {"success": result.success, "rule_count": result.rule_count},
            )
            await session.commit()

            if result.success:
                # Send sync completion notification
                await send_system_notification(
                    session,
                    "sigmahq_sync_complete",
                    {
                        "rule_count": result.rule_count,
                        "new_rules": result.new_rules if hasattr(result, "new_rules") else 0,
                        "message": result.message,
                    },
                )

                # Send new rules notification if there are new rules
                if hasattr(result, "new_rules") and result.new_rules > 0:
                    await send_system_notification(
                        session,
                        "new_rules_available",
                        {
                            "count": result.new_rules,
                            "source": "sigmahq",
                        },
                    )
            else:
                # Send sync failure notification
                await send_system_notification(
                    session,
                    "sync_failure",
                    {
                        "sync_type": "sigmahq",
                        "error": result.error if hasattr(result, "error") else result.message,
                    },
                )

            logger.info(f"SigmaHQ sync completed: {result.message}")

        except Exception as e:
            logger.error(f"Scheduled SigmaHQ sync failed: {e}")
            # Send sync failure notification
            try:
                await send_system_notification(
                    session,
                    "sync_failure",
                    {"sync_type": "sigmahq", "error": str(e)},
                )
            except Exception:
                pass  # Don't fail on notification errors
        finally:
            await session.close()

    async def _run_health_check(self):
        """Execute health monitoring check."""
        from app.services.health_monitor import check_index_health

        logger.debug("Running scheduled health check")
        session = await self._get_session()
        try:
            issues = await check_index_health(session)
            if issues:
                logger.info(f"Health check found {len(issues)} issues")
        except Exception as e:
            logger.error(f"Scheduled health check failed: {e}")
        finally:
            await session.close()

    def get_next_run_time(self, job_id: str) -> datetime | None:
        """Get the next scheduled run time for a job."""
        job = scheduler.get_job(job_id)
        if job:
            return job.next_run_time
        return None


# Singleton instance
scheduler_service = SchedulerService()
