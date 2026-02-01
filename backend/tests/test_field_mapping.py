"""Tests for field mapping service."""

import uuid

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.field_mapping import FieldMapping, MappingOrigin
from app.models.index_pattern import IndexPattern
from app.models.user import User
from app.services.field_mapping import (
    create_mapping,
    delete_mapping,
    get_mappings,
    resolve_mappings,
    update_mapping,
)


class TestResolveMappings:
    """Test mapping resolution logic."""

    @pytest_asyncio.fixture
    async def index_pattern(self, test_session: AsyncSession) -> IndexPattern:
        pattern = IndexPattern(
            id=uuid.uuid4(),
            name="test-pattern",
            pattern="test-*",
            percolator_index=".percolator-test",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        return pattern

    @pytest_asyncio.fixture
    async def another_index_pattern(self, test_session: AsyncSession) -> IndexPattern:
        pattern = IndexPattern(
            id=uuid.uuid4(),
            name="another-pattern",
            pattern="another-*",
            percolator_index=".percolator-another",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        return pattern

    @pytest_asyncio.fixture
    async def source_ip_mapping(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ) -> FieldMapping:
        mapping = FieldMapping(
            sigma_field="SourceIp",
            target_field="src_ip",
            origin=MappingOrigin.MANUAL,
            created_by=test_user.id,
            index_pattern_id=index_pattern.id,
        )
        test_session.add(mapping)
        await test_session.commit()
        await test_session.refresh(mapping)
        return mapping

    @pytest_asyncio.fixture
    async def user_mapping(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ) -> FieldMapping:
        mapping = FieldMapping(
            sigma_field="User",
            target_field="acct",
            origin=MappingOrigin.MANUAL,
            created_by=test_user.id,
            index_pattern_id=index_pattern.id,
        )
        test_session.add(mapping)
        await test_session.commit()
        await test_session.refresh(mapping)
        return mapping

    async def test_resolve_index_mapping(
        self, test_session: AsyncSession, source_ip_mapping: FieldMapping, index_pattern: IndexPattern
    ):
        """Per-index mapping should resolve for that index pattern."""
        result = await resolve_mappings(
            test_session, ["SourceIp"], index_pattern.id
        )
        assert result["SourceIp"] == "src_ip"

    async def test_resolve_user_mapping(
        self, test_session: AsyncSession, user_mapping: FieldMapping, index_pattern: IndexPattern
    ):
        """User field mapping should resolve correctly."""
        result = await resolve_mappings(
            test_session, ["User"], index_pattern.id
        )
        assert result["User"] == "acct"

    async def test_mapping_isolated_to_index_pattern(
        self,
        test_session: AsyncSession,
        test_user: User,
        index_pattern: IndexPattern,
        another_index_pattern: IndexPattern,
    ):
        """Mappings should be isolated to their index pattern."""
        # Create mapping for one index pattern
        mapping = FieldMapping(
            sigma_field="User",
            target_field="username",
            origin=MappingOrigin.MANUAL,
            created_by=test_user.id,
            index_pattern_id=index_pattern.id,
        )
        test_session.add(mapping)
        await test_session.commit()

        # Should resolve for its own index pattern
        result = await resolve_mappings(
            test_session, ["User"], index_pattern.id
        )
        assert result["User"] == "username"

        # Should NOT resolve for different index pattern
        result = await resolve_mappings(
            test_session, ["User"], another_index_pattern.id
        )
        assert result["User"] is None

    async def test_unmapped_field_returns_none(
        self, test_session: AsyncSession, index_pattern: IndexPattern
    ):
        """Unmapped fields should return None."""
        result = await resolve_mappings(
            test_session, ["UnknownField"], index_pattern.id
        )
        assert result["UnknownField"] is None

    async def test_resolve_multiple_fields(
        self,
        test_session: AsyncSession,
        source_ip_mapping: FieldMapping,
        user_mapping: FieldMapping,
        index_pattern: IndexPattern,
    ):
        """Should resolve multiple fields at once."""
        result = await resolve_mappings(
            test_session, ["SourceIp", "User", "Unknown"], index_pattern.id
        )
        assert result == {
            "SourceIp": "src_ip",
            "User": "acct",
            "Unknown": None,
        }


class TestCRUDOperations:
    """Test CRUD operations for field mappings."""

    @pytest_asyncio.fixture
    async def index_pattern(self, test_session: AsyncSession) -> IndexPattern:
        pattern = IndexPattern(
            id=uuid.uuid4(),
            name="crud-test",
            pattern="crud-*",
            percolator_index=".percolator-crud",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)
        return pattern

    async def test_create_mapping(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ):
        """Should create a new mapping."""
        mapping = await create_mapping(
            test_session,
            sigma_field="TestField",
            target_field="test_field",
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
            origin=MappingOrigin.MANUAL,
        )
        assert mapping.sigma_field == "TestField"
        assert mapping.target_field == "test_field"

    async def test_get_mappings_by_index(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ):
        """Should filter mappings by index pattern."""
        await create_mapping(
            test_session,
            sigma_field="IndexField",
            target_field="index_field",
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
        )
        mappings = await get_mappings(test_session, index_pattern_id=index_pattern.id)
        assert all(m.index_pattern_id == index_pattern.id for m in mappings)

    async def test_update_mapping(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ):
        """Should update an existing mapping."""
        mapping = await create_mapping(
            test_session,
            sigma_field="UpdateField",
            target_field="old_field",
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
        )
        updated = await update_mapping(
            test_session, mapping.id, target_field="new_field"
        )
        assert updated.target_field == "new_field"

    async def test_delete_mapping(
        self, test_session: AsyncSession, test_user: User, index_pattern: IndexPattern
    ):
        """Should delete a mapping."""
        mapping = await create_mapping(
            test_session,
            sigma_field="DeleteField",
            target_field="delete_field",
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
        )
        result = await delete_mapping(test_session, mapping.id)
        assert result is True

        # Verify deleted
        mappings = await get_mappings(test_session, index_pattern_id=index_pattern.id)
        assert all(m.id != mapping.id for m in mappings)
