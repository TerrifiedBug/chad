"""Schemas for the Detection-as-Code CI endpoints (rule lint + backtest + coverage)."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RuleCICheckRequest(BaseModel):
    """Body for POST /rule-ci/check — run CI over an arbitrary rule YAML."""

    yaml_content: str = Field(..., min_length=1)
    index_pattern_id: UUID | None = None
    # Match count above which the FP backtest flags the rule as noisy.
    fp_threshold: int | None = Field(default=None, ge=1, le=10_000_000)
    # How far back the backtest scans.
    backtest_days: int | None = Field(default=None, ge=1, le=365)
    # Allow callers to opt out of the (potentially expensive) backtest.
    run_backtest: bool = True


class RuleCICheckItem(BaseModel):
    """A single CI check result."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str  # pass | warn | fail | skipped
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class RuleCIReport(BaseModel):
    """Aggregate CI report returned to the client."""

    model_config = ConfigDict(from_attributes=True)

    passed: bool
    checks: list[RuleCICheckItem]
    summary: str
