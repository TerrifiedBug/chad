"""Tests for IndexPatternPollState model."""

from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern
from app.models.poll_state import IndexPatternPollState


class TestIndexPatternPollState:
    @pytest_asyncio.fixture
    async def index_pattern(self, test_session: AsyncSession) -> IndexPattern:
        pattern = IndexPattern(
            name="Test Pattern",
            pattern="logs-test-*",
            percolator_index="chad-percolator-logs-test",
            mode="pull",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        return pattern

    async def test_poll_state_creation(
        self, test_session: AsyncSession, index_pattern: IndexPattern
    ):
        """Should create poll state for an index pattern."""
        poll_state = IndexPatternPollState(
            index_pattern_id=index_pattern.id,
            last_poll_at=datetime.now(UTC),
            last_poll_status="success",
        )
        test_session.add(poll_state)
        await test_session.commit()
        await test_session.refresh(poll_state)

        assert poll_state.index_pattern_id == index_pattern.id
        assert poll_state.last_poll_status == "success"
        assert poll_state.last_error is None

    async def test_poll_state_cascade_delete(
        self, test_session: AsyncSession, index_pattern: IndexPattern
    ):
        """Poll state should be deleted when index pattern is deleted."""
        poll_state = IndexPatternPollState(
            index_pattern_id=index_pattern.id,
            last_poll_status="success",
        )
        test_session.add(poll_state)
        await test_session.commit()

        # Delete the index pattern
        await test_session.delete(index_pattern)
        await test_session.commit()

        # Poll state should be gone
        result = await test_session.execute(
            select(IndexPatternPollState).where(
                IndexPatternPollState.index_pattern_id == index_pattern.id
            )
        )
        assert result.scalar_one_or_none() is None

    async def test_poll_state_error_tracking(
        self, test_session: AsyncSession, index_pattern: IndexPattern
    ):
        """Should track error status and message."""
        poll_state = IndexPatternPollState(
            index_pattern_id=index_pattern.id,
            last_poll_status="error",
            last_error="OpenSearch connection timeout",
        )
        test_session.add(poll_state)
        await test_session.commit()
        await test_session.refresh(poll_state)

        assert poll_state.last_poll_status == "error"
        assert poll_state.last_error == "OpenSearch connection timeout"
