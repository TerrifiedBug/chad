"""run_historical_test with candidate must_not_clauses (mocked OpenSearch).

Asserts the candidate exception is injected into the combined query's
bool.must_not, and that omitting must_not_clauses leaves the query unchanged
(backward-compatible additive param).
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.rule_exception import ExceptionOperator
from app.services.rule_testing import ExceptionClause, run_historical_test


def _rule():
    return SimpleNamespace(
        id="rule-1",
        yaml_content="title: t\nstatus: test\nlogsource:\n  product: x\ndetection:\n  sel:\n    a: '1'\n  condition: sel",  # noqa: E501
        index_pattern_id=None,
        index_pattern=SimpleNamespace(pattern="logs-*"),
    )


def _db_returning_rule(rule):
    db = MagicMock()
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = rule
    db.execute = AsyncMock(return_value=exec_result)
    return db


def _os_client(matches: int):
    client = MagicMock()
    # count() is called for total-in-range, then for matches.
    client.count.side_effect = [{"count": 100}, {"count": matches}]
    client.search.return_value = {"hits": {"hits": []}}
    return client


@pytest.mark.asyncio
async def test_must_not_clause_injected_into_query():
    rule = _rule()
    db = _db_returning_rule(rule)
    os_client = _os_client(matches=3)
    translation = SimpleNamespace(
        success=True,
        errors=None,
        fields=set(),
        query={"query": {"query_string": {"query": "a:1"}}},
    )
    with patch(
        "app.services.rule_testing.sigma_service.translate_and_validate",
        return_value=translation,
    ):
        result = await run_historical_test(
            db=db,
            os_client=os_client,
            rule_id=rule.id,
            start_date=datetime(2026, 1, 1, tzinfo=UTC),
            end_date=datetime(2026, 1, 2, tzinfo=UTC),
            must_not_clauses=[
                ExceptionClause(
                    field="user.name",
                    operator=ExceptionOperator.EQUALS,
                    value="svc_backup",
                )
            ],
        )

    assert result.error is None
    assert result.total_matches == 3
    # The candidate exception must appear in the combined query's must_not.
    must_not = result.query_executed["query"]["bool"]["must_not"]
    assert {"match_phrase": {"user.name": "svc_backup"}} in must_not


@pytest.mark.asyncio
async def test_no_clauses_omits_must_not_key():
    rule = _rule()
    db = _db_returning_rule(rule)
    os_client = _os_client(matches=42)
    translation = SimpleNamespace(
        success=True,
        errors=None,
        fields=set(),
        query={"query": {"query_string": {"query": "a:1"}}},
    )
    with patch(
        "app.services.rule_testing.sigma_service.translate_and_validate",
        return_value=translation,
    ):
        result = await run_historical_test(
            db=db,
            os_client=os_client,
            rule_id=rule.id,
            start_date=datetime(2026, 1, 1, tzinfo=UTC),
            end_date=datetime(2026, 1, 2, tzinfo=UTC),
        )

    assert result.total_matches == 42
    # Backward-compatible: no must_not key when no candidate clauses supplied.
    assert "must_not" not in result.query_executed["query"]["bool"]
