"""
External API endpoints authenticated via API keys.

These endpoints provide read-only access to CHAD data for external integrations
like dashboards, SIEM systems, and automation tools.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.api_keys import validate_api_key
from app.api.deps import get_opensearch_client_optional
from app.db.session import get_db
from app.models.api_key import APIKey
from app.models.rule import Rule, RuleStatus
from app.models.user import User
from app.services.api_rate_limit import check_api_key_rate_limit

router = APIRouter(prefix="/external", tags=["external"])


async def get_api_key_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> User:
    """
    Dependency to authenticate requests via API key.

    Expects the API key in the X-API-Key header.
    Enforces rate limiting per API key.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide X-API-Key header.",
        )

    user = await validate_api_key(x_api_key, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    # Get the API key object to use its ID for rate limiting
    key_prefix = x_api_key[:12] if len(x_api_key) >= 12 else x_api_key
    result = await db.execute(
        select(APIKey).where(APIKey.key_prefix == key_prefix, APIKey.is_active.is_(True))
    )
    api_key = result.scalar_one_or_none()

    if api_key:
        # Enforce rate limit per API key
        await check_api_key_rate_limit(str(api_key.id))

    return user


@router.get("/rules")
async def list_rules_external(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_api_key_user)],
    status_filter: RuleStatus | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    List rules (read-only).

    Returns a paginated list of rules with optional status filtering.
    """
    query = select(Rule).options(selectinload(Rule.index_pattern))

    if status_filter:
        query = query.where(Rule.status == status_filter)

    # Get total count
    count_query = select(func.count()).select_from(Rule)
    if status_filter:
        count_query = count_query.where(Rule.status == status_filter)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(Rule.updated_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    rules = result.scalars().all()

    return {
        "items": [
            {
                "id": str(rule.id),
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "status": rule.status.value,
                "index_pattern": rule.index_pattern.name if rule.index_pattern else None,
                "deployed_at": rule.deployed_at.isoformat() if rule.deployed_at else None,
                "created_at": rule.created_at.isoformat(),
                "updated_at": rule.updated_at.isoformat(),
            }
            for rule in rules
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/rules/{rule_id}")
async def get_rule_external(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_api_key_user)],
):
    """Get a specific rule by ID (read-only)."""
    result = await db.execute(
        select(Rule)
        .options(selectinload(Rule.index_pattern))
        .where(Rule.id == str(rule_id))
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    return {
        "id": str(rule.id),
        "title": rule.title,
        "description": rule.description,
        "severity": rule.severity,
        "status": rule.status.value,
        "yaml_content": rule.yaml_content,
        "index_pattern": {
            "id": str(rule.index_pattern.id),
            "name": rule.index_pattern.name,
            "pattern": rule.index_pattern.pattern,
        } if rule.index_pattern else None,
        "deployed_at": rule.deployed_at.isoformat() if rule.deployed_at else None,
        "deployed_version": rule.deployed_version,
        "created_at": rule.created_at.isoformat(),
        "updated_at": rule.updated_at.isoformat(),
    }


@router.get("/alerts")
async def list_alerts_external(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_api_key_user)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    rule_id: str | None = Query(None),
    start_time: str | None = Query(None, description="ISO 8601 datetime"),
    end_time: str | None = Query(None, description="ISO 8601 datetime"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    List alerts from OpenSearch.

    Returns paginated list of alerts with optional filters.
    """
    if os_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch not configured",
        )

    # Build query
    must = []
    if status_filter:
        must.append({"term": {"status": status_filter}})
    if severity:
        must.append({"term": {"severity": severity}})
    if rule_id:
        must.append({"term": {"rule_id": rule_id}})

    # Time range filter
    if start_time or end_time:
        range_filter = {}
        if start_time:
            range_filter["gte"] = start_time
        if end_time:
            range_filter["lte"] = end_time
        must.append({"range": {"created_at": range_filter}})

    query = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"created_at": {"order": "desc"}}],
        "from": offset,
        "size": limit,
    }

    try:
        result = os_client.search(index="chad-alerts-*", body=query)
        hits = result.get("hits", {})

        return {
            "items": [hit["_source"] for hit in hits.get("hits", [])],
            "total": hits.get("total", {}).get("value", 0),
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query alerts: {str(e)}",
        )


@router.get("/stats")
async def get_stats_external(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_api_key_user)],
):
    """Get summary statistics (read-only)."""
    # Count rules by status
    result = await db.execute(
        select(Rule.status, func.count(Rule.id))
        .group_by(Rule.status)
    )
    rules_by_status = {status.value: count for status, count in result.all()}

    # Total rules
    total_rules = sum(rules_by_status.values())

    return {
        "rules": {
            "total": total_rules,
            "by_status": rules_by_status,
        },
    }
