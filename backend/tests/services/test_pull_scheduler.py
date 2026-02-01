"""Tests for pull mode scheduling."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestSchedulePullJobs:
    @pytest.mark.asyncio
    async def test_schedule_pull_jobs_for_pull_patterns(self):
        """Should schedule jobs only for pull-mode patterns."""
        from app.services.pull_detector import schedule_pull_jobs

        mock_scheduler = MagicMock()
        mock_scheduler.add_job = MagicMock()

        mock_patterns = [
            MagicMock(id="pattern-1", mode="push", poll_interval_minutes=5),
            MagicMock(id="pattern-2", mode="pull", poll_interval_minutes=10),
            MagicMock(id="pattern-3", mode="pull", poll_interval_minutes=5),
        ]

        with patch("app.services.pull_detector.get_settings") as mock_settings:
            mock_settings.return_value.is_pull_only = False
            await schedule_pull_jobs(mock_scheduler, mock_patterns)

        # Should only add jobs for pull patterns (2 jobs)
        assert mock_scheduler.add_job.call_count == 2

    @pytest.mark.asyncio
    async def test_schedule_all_patterns_in_pull_only_mode(self):
        """In pull-only deployment, should schedule all patterns."""
        from app.services.pull_detector import schedule_pull_jobs

        mock_scheduler = MagicMock()
        mock_scheduler.add_job = MagicMock()

        mock_patterns = [
            MagicMock(id="pattern-1", mode="push", poll_interval_minutes=5),
            MagicMock(id="pattern-2", mode="pull", poll_interval_minutes=10),
        ]

        with patch("app.services.pull_detector.get_settings") as mock_settings:
            mock_settings.return_value.is_pull_only = True
            await schedule_pull_jobs(mock_scheduler, mock_patterns)

        # In pull-only mode, all patterns should be scheduled
        assert mock_scheduler.add_job.call_count == 2
