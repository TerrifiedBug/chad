"""Pydantic schemas for coverage-gap rule recommendations (Feature F6)."""
from pydantic import BaseModel, ConfigDict


class SuggestedRuleResponse(BaseModel):
    """A SigmaHQ rule suggested to help close a coverage gap."""

    model_config = ConfigDict(from_attributes=True)

    title: str
    path: str
    severity: str
    rule_type: str  # "detection" | "threat_hunting" | "emerging_threats"
    # True when the org already maps every Sigma field the rule uses.
    compatible: bool


class CoverageRecommendationResponse(BaseModel):
    """A prioritised recommendation for one uncovered/weakly-covered technique."""

    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    technique_name: str
    tactic: str
    current_coverage: int  # deployed rule count today (0 == fully uncovered)
    reason: str
    suggested_rule_titles: list[str]
    suggested_rules: list[SuggestedRuleResponse]
    priority: float


class CoverageRecommendationsResponse(BaseModel):
    """Envelope returned by GET /recommendations/coverage."""

    recommendations: list[CoverageRecommendationResponse]
    total: int
