"""Tests for IOC query builder for Pull Mode."""

import pytest

from app.services.ti.ioc_index import INDICATOR_INDEX_NAME
from app.services.ti.ioc_query_builder import IOCQueryBuilder


@pytest.fixture
def sample_field_mappings():
    """Sample IOC field mappings."""
    return {
        "ip-dst": ["destination.ip"],
        "ip-src": ["source.ip"],
        "domain": ["dns.question.name"],
    }


def test_build_join_query(sample_field_mappings):
    """Test building OpenSearch join query."""
    builder = IOCQueryBuilder()
    query = builder.build_join_query(
        field_mappings=sample_field_mappings,
        time_field="@timestamp",
        lookback_minutes=15,
    )

    assert "query" in query
    assert "bool" in query["query"]
    assert "must" in query["query"]["bool"]
    assert "should" in query["query"]["bool"]

    # Check time range filter
    time_range = query["query"]["bool"]["must"][0]
    assert "range" in time_range
    assert "@timestamp" in time_range["range"]

    # Check should clauses for each field mapping
    should_clauses = query["query"]["bool"]["should"]
    assert len(should_clauses) == 3  # ip-dst, ip-src, domain

    # Check minimum_should_match
    assert query["query"]["bool"]["minimum_should_match"] == 1


def test_build_join_query_uses_indicator_index(sample_field_mappings):
    """Test that join query references indicator index."""
    builder = IOCQueryBuilder()
    query = builder.build_join_query(
        field_mappings=sample_field_mappings,
        time_field="@timestamp",
        lookback_minutes=15,
    )

    # Each should clause should reference the indicator index
    for clause in query["query"]["bool"]["should"]:
        terms_clause = clause.get("terms", {})
        for field_terms in terms_clause.values():
            assert field_terms.get("index") == INDICATOR_INDEX_NAME
            assert field_terms.get("path") == "indicator.value"


def test_build_join_query_custom_time_field(sample_field_mappings):
    """Test building query with custom timestamp field."""
    builder = IOCQueryBuilder()
    query = builder.build_join_query(
        field_mappings=sample_field_mappings,
        time_field="event.created",
        lookback_minutes=30,
    )

    time_range = query["query"]["bool"]["must"][0]
    assert "event.created" in time_range["range"]
    assert time_range["range"]["event.created"]["gte"] == "now-30m"


def test_build_join_query_empty_mappings():
    """Test building query with empty mappings."""
    builder = IOCQueryBuilder()
    query = builder.build_join_query(
        field_mappings={},
        time_field="@timestamp",
        lookback_minutes=15,
    )

    # Should still be valid query but with no should clauses
    assert query["query"]["bool"]["should"] == []
    assert query["query"]["bool"]["minimum_should_match"] == 0
