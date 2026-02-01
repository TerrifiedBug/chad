"""Tests for IndexPattern model mode field."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern


class TestIndexPatternMode:
    @pytest_asyncio.fixture
    async def index_pattern(self, test_session: AsyncSession) -> IndexPattern:
        pattern = IndexPattern(
            name="Test Pattern",
            pattern="logs-test-*",
            percolator_index="chad-percolator-logs-test",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        return pattern

    async def test_mode_defaults_to_push(self, index_pattern: IndexPattern):
        """mode should default to 'push' for backward compatibility."""
        assert index_pattern.mode == "push"

    async def test_mode_can_be_set_to_pull(self, test_session: AsyncSession):
        """mode should accept 'pull' value."""
        pattern = IndexPattern(
            name="Pull Pattern",
            pattern="logs-pull-*",
            percolator_index="chad-percolator-logs-pull",
            mode="pull",
            poll_interval_minutes=10,
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        assert pattern.mode == "pull"
        assert pattern.poll_interval_minutes == 10

    async def test_poll_interval_defaults_to_5(self, test_session: AsyncSession):
        """poll_interval_minutes should default to 5."""
        pattern = IndexPattern(
            name="Default Poll Pattern",
            pattern="logs-default-*",
            percolator_index="chad-percolator-logs-default",
            mode="pull",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        assert pattern.poll_interval_minutes == 5
