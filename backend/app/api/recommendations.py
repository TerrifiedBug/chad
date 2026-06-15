"""
Coverage-gap rule recommendation API (Feature F6).

Turns the ATT&CK coverage map into a "deploy these next" list. Read-only, so
any authenticated user may view it (matches the ATT&CK matrix/coverage
endpoints, which also use ``get_current_user``).
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client_optional
from app.db.session import get_db
from app.models.user import User
from app.schemas.recommendations import (
    CoverageRecommendationResponse,
    CoverageRecommendationsResponse,
)
from app.services.coverage_recommendations import recommend

router = APIRouter(prefix="/recommendations", tags=["recommendations"])


@router.get("/coverage", response_model=CoverageRecommendationsResponse)
async def get_coverage_recommendations(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    os_client: Annotated[object | None, Depends(get_opensearch_client_optional)],
    limit: int = Query(10, ge=1, le=50, description="Max recommendations to return"),
) -> CoverageRecommendationsResponse:
    """
    Recommend SigmaHQ rules to deploy next, prioritised by coverage gaps.

    Computes uncovered/weakly-covered ATT&CK techniques from existing coverage
    data and suggests concrete SigmaHQ rules that map to each gap, weighted by
    technique prevalence, rule severity, and compatibility with the org's
    existing field mappings.
    """
    items = await recommend(db, os_client, limit=limit)

    return CoverageRecommendationsResponse(
        recommendations=[
            CoverageRecommendationResponse.model_validate(item) for item in items
        ],
        total=len(items),
    )
