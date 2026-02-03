"""Integration tests for scheduler and background jobs."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.scheduler import scheduler_service


@pytest.mark.skip(reason="Tests use API (is_running, register_job, etc.) that was planned but never implemented")
@pytest.mark.asyncio
async def test_scheduler_service_lifecycle(db_session: AsyncSession):
    """Test starting and stopping the scheduler service."""
    # Start scheduler
    scheduler_service.start()

    # Verify it's running
    assert scheduler_service.is_running is True

    # Stop scheduler
    scheduler_service.stop()

    # Verify it's stopped
    assert scheduler_service.is_running is False


@pytest.mark.skip(reason="Tests use API (register_job, unregister_job) that was planned but never implemented")
@pytest.mark.asyncio
async def test_scheduler_job_registration(db_session: AsyncSession):
    """Test registering and running scheduler jobs."""
    # Start scheduler
    scheduler_service.start()

    try:
        # Register a test job
        job_ran = []

        async def test_job():
            job_ran.append(True)

        scheduler_service.register_job(
            job_id="test_job",
            job_func=test_job,
            trigger_type="interval",
            trigger_args={"seconds": 1},
        )

        # Wait for job to run
        import asyncio
        await asyncio.sleep(2)

        # Verify job ran
        assert len(job_ran) > 0

        # Unregister job
        scheduler_service.unregister_job("test_job")

    finally:
        scheduler_service.stop()


@pytest.mark.skip(reason="Tests use API (list_jobs) that was planned but never implemented")
@pytest.mark.asyncio
async def test_scheduler_job_persistence(db_session: AsyncSession):
    """Test that scheduler jobs are persisted to database."""
    # Start scheduler
    scheduler_service.start()

    try:
        # Save job settings to database
        from app.services.settings import set_setting

        await set_setting(
            db_session,
            "scheduler_jobs",
            {
                "jobs": [
                    {
                        "job_id": "test_health_check",
                        "job_func": "health_check_opensearch",
                        "trigger_type": "interval",
                        "trigger_args": {"seconds": 300},
                    }
                ]
            }
        )

        # Sync jobs from settings
        await scheduler_service.sync_jobs_from_settings()

        # Verify jobs are registered
        jobs = scheduler_service.list_jobs()
        assert "test_health_check" in jobs

    finally:
        scheduler_service.stop()


@pytest.mark.skip(reason="Tests use API (register_job, unregister_job, is_running) that was planned but never implemented")
@pytest.mark.asyncio
async def test_scheduler_error_handling(db_session: AsyncSession):
    """Test that scheduler handles job errors gracefully."""
    # Start scheduler
    scheduler_service.start()

    try:
        error_count = []

        async def failing_job():
            error_count.append(1)
            raise Exception("Test error")

        scheduler_service.register_job(
            job_id="failing_job",
            job_func=failing_job,
            trigger_type="interval",
            trigger_args={"seconds": 1},
        )

        # Wait for multiple runs
        import asyncio
        await asyncio.sleep(3)

        # Verify job ran but errors were caught
        assert len(error_count) >= 2  # Job ran at least twice

        # Scheduler is still running (didn't crash)
        assert scheduler_service.is_running is True

        # Unregister job
        scheduler_service.unregister_job("failing_job")

    finally:
        scheduler_service.stop()
