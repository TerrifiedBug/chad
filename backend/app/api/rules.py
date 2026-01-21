from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.rule import Rule, RuleStatus, RuleVersion
from app.models.user import User
from app.schemas.rule import RuleCreate, RuleDetailResponse, RuleResponse, RuleUpdate

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    status_filter: RuleStatus | None = None,
    skip: int = 0,
    limit: int = 100,
):
    query = select(Rule).offset(skip).limit(limit)
    if status_filter:
        query = query.where(Rule.status == status_filter)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rule = Rule(
        title=rule_data.title,
        description=rule_data.description,
        yaml_content=rule_data.yaml_content,
        severity=rule_data.severity,
        index_pattern_id=rule_data.index_pattern_id,
        created_by=current_user.id,
        status=RuleStatus.DISABLED,
    )
    db.add(rule)

    # Create initial version
    version = RuleVersion(
        rule_id=rule.id,
        version_number=1,
        yaml_content=rule_data.yaml_content,
        changed_by=current_user.id,
    )
    db.add(version)

    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=RuleDetailResponse)
async def get_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(Rule)
        .where(Rule.id == rule_id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )
    return rule


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_data: RuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    update_data = rule_data.model_dump(exclude_unset=True)

    # If yaml_content changed, create new version
    if "yaml_content" in update_data and update_data["yaml_content"] != rule.yaml_content:
        # Get latest version number
        version_result = await db.execute(
            select(RuleVersion)
            .where(RuleVersion.rule_id == rule_id)
            .order_by(RuleVersion.version_number.desc())
            .limit(1)
        )
        latest_version = version_result.scalar_one_or_none()
        next_version = (latest_version.version_number + 1) if latest_version else 1

        new_version = RuleVersion(
            rule_id=rule_id,
            version_number=next_version,
            yaml_content=update_data["yaml_content"],
            changed_by=current_user.id,
        )
        db.add(new_version)

    for field, value in update_data.items():
        setattr(rule, field, value)

    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    await db.delete(rule)
    await db.commit()
