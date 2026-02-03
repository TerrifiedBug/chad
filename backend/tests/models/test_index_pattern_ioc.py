"""Tests for IndexPattern IOC detection fields."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.index_pattern import IndexPattern


@pytest.mark.asyncio
async def test_index_pattern_has_ioc_detection_enabled_field(db_session: AsyncSession):
    """Test IndexPattern has ioc_detection_enabled field."""
    pattern = IndexPattern(
        name="test-ioc-pattern",
        pattern="test-*",
        percolator_index="percolate-test",
        ioc_detection_enabled=True,
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    assert pattern.ioc_detection_enabled is True


@pytest.mark.asyncio
async def test_index_pattern_ioc_detection_enabled_default_false(db_session: AsyncSession):
    """Test ioc_detection_enabled defaults to False."""
    pattern = IndexPattern(
        name="test-default-pattern",
        pattern="default-*",
        percolator_index="percolate-default",
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    assert pattern.ioc_detection_enabled is False


@pytest.mark.asyncio
async def test_index_pattern_has_ioc_field_mappings(db_session: AsyncSession):
    """Test IndexPattern has ioc_field_mappings JSONB field."""
    mappings = {
        "ip-dst": ["destination.ip", "winlog.event_data.DestinationIp"],
        "ip-src": ["source.ip"],
        "domain": ["dns.question.name"],
        "md5": ["file.hash.md5", "process.hash.md5"],
        "sha256": ["file.hash.sha256"],
        "url": ["url.full"],
    }

    pattern = IndexPattern(
        name="test-mappings-pattern",
        pattern="mappings-*",
        percolator_index="percolate-mappings",
        ioc_detection_enabled=True,
        ioc_field_mappings=mappings,
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    assert pattern.ioc_field_mappings == mappings
    assert "destination.ip" in pattern.ioc_field_mappings["ip-dst"]


@pytest.mark.asyncio
async def test_index_pattern_ioc_field_mappings_nullable(db_session: AsyncSession):
    """Test ioc_field_mappings can be null."""
    pattern = IndexPattern(
        name="test-null-mappings",
        pattern="null-*",
        percolator_index="percolate-null",
        ioc_detection_enabled=False,
        ioc_field_mappings=None,
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    assert pattern.ioc_field_mappings is None
