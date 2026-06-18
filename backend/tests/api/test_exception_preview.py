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
