"""Exception preview request/response schema behavior."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.rule_exception import ExceptionOperator
from app.schemas.rule_exception import (
    ExceptionPreviewClause,
    ExceptionPreviewRequest,
    ExceptionPreviewResponse,
)


def test_preview_request_accepts_clauses():
    req = ExceptionPreviewRequest(
        start_date=datetime(2026, 1, 1, tzinfo=UTC),
        end_date=datetime(2026, 1, 2, tzinfo=UTC),
        clauses=[
            ExceptionPreviewClause(
                field="user.name",
                operator=ExceptionOperator.EQUALS,
                value="svc_backup",
            )
        ],
    )
    assert req.clauses[0].field == "user.name"
    assert req.limit == 500  # default mirrors HistoricalTestRequest


def test_preview_request_requires_at_least_one_clause():
    with pytest.raises(ValidationError):
        ExceptionPreviewRequest(
            start_date=datetime(2026, 1, 1, tzinfo=UTC),
            end_date=datetime(2026, 1, 2, tzinfo=UTC),
            clauses=[],
        )


def test_preview_response_shape():
    resp = ExceptionPreviewResponse(total_matches=10, suppressed=4, remaining=6)
    assert resp.suppressed == 4
    assert resp.remaining == 6


def test_preview_endpoint_computes_delta(monkeypatch):
    """suppressed = baseline_total - candidate_total; remaining = candidate_total."""
    from app.api.rules import exceptions as exc_mod
    from app.services.rule_testing import HistoricalTestResult

    calls = []

    async def fake_run(*, must_not_clauses=None, **kwargs):
        calls.append(must_not_clauses)
        total = 10 if not must_not_clauses else 6
        return HistoricalTestResult(
            total_scanned=100,
            total_matches=total,
            matches=[],
            truncated=False,
        )

    monkeypatch.setattr(exc_mod, "run_historical_test", fake_run)

    import asyncio

    async def _go():
        from datetime import UTC, datetime
        from uuid import uuid4

        from app.schemas.rule_exception import (
            ExceptionPreviewClause,
            ExceptionPreviewRequest,
        )

        req = ExceptionPreviewRequest(
            start_date=datetime(2026, 1, 1, tzinfo=UTC),
            end_date=datetime(2026, 1, 2, tzinfo=UTC),
            clauses=[
                ExceptionPreviewClause(field="user.name", value="svc_backup")
            ],
        )
        return await exc_mod.preview_rule_exception(
            rule_id=uuid4(),
            preview_data=req,
            os_client=object(),
            db=object(),
            _=object(),
        )

    resp = asyncio.run(_go())
    assert resp.total_matches == 10
    assert resp.suppressed == 4
    assert resp.remaining == 6
    # Baseline call has no clauses; candidate call has exactly one.
    assert calls[0] is None
    assert len(calls[1]) == 1
