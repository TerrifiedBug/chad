# backend/app/api/sigmahq.py
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import yaml

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.rule import Rule, RuleSource, RuleStatus, RuleVersion
from app.models.user import User
from app.schemas.sigmahq import (
    SigmaHQCategoryTree,
    SigmaHQImportRequest,
    SigmaHQImportResponse,
    SigmaHQRuleContentResponse,
    SigmaHQRulesListResponse,
    SigmaHQSearchRequest,
    SigmaHQStatusResponse,
    SigmaHQSyncResponse,
)
from app.services.sigmahq import sigmahq_service

router = APIRouter(prefix="/sigmahq", tags=["sigmahq"])


@router.get("/status", response_model=SigmaHQStatusResponse)
async def get_status(
    _: Annotated[User, Depends(get_current_user)],
):
    """Get SigmaHQ repository sync status."""
    is_cloned = sigmahq_service.is_repo_cloned()

    if not is_cloned:
        return SigmaHQStatusResponse(cloned=False)

    return SigmaHQStatusResponse(
        cloned=True,
        commit_hash=sigmahq_service.get_current_commit_hash(),
        rule_count=sigmahq_service.count_rules(),
        repo_url=sigmahq_service.DEFAULT_REPO_URL,
    )


@router.post("/sync", response_model=SigmaHQSyncResponse)
async def sync_repo(
    _: Annotated[User, Depends(require_admin)],
):
    """Sync (clone or pull) the SigmaHQ repository."""
    if sigmahq_service.is_repo_cloned():
        result = sigmahq_service.pull_repo()
    else:
        result = sigmahq_service.clone_repo()

    return SigmaHQSyncResponse(
        success=result.success,
        message=result.message,
        commit_hash=result.commit_hash,
        rule_count=result.rule_count,
        error=result.error,
    )


@router.get("/rules", response_model=SigmaHQCategoryTree)
async def get_category_tree(
    _: Annotated[User, Depends(get_current_user)],
):
    """Get the category tree structure of SigmaHQ rules."""
    if not sigmahq_service.is_repo_cloned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SigmaHQ repository not cloned. Sync first.",
        )

    return SigmaHQCategoryTree(categories=sigmahq_service.get_category_tree())


@router.get("/rules/list/{category_path:path}", response_model=SigmaHQRulesListResponse)
async def list_rules_in_category(
    category_path: str,
    _: Annotated[User, Depends(get_current_user)],
):
    """List rules in a specific category."""
    if not sigmahq_service.is_repo_cloned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SigmaHQ repository not cloned. Sync first.",
        )

    rules = sigmahq_service.list_rules_in_category(category_path)
    return SigmaHQRulesListResponse(rules=rules, total=len(rules))


@router.get("/rules/{rule_path:path}", response_model=SigmaHQRuleContentResponse)
async def get_rule_content(
    rule_path: str,
    _: Annotated[User, Depends(get_current_user)],
):
    """Get the content of a specific SigmaHQ rule."""
    if not sigmahq_service.is_repo_cloned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SigmaHQ repository not cloned. Sync first.",
        )

    content = sigmahq_service.get_rule_content(rule_path)

    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Parse metadata
    try:
        metadata = yaml.safe_load(content)
    except Exception:
        metadata = None

    return SigmaHQRuleContentResponse(
        path=rule_path,
        content=content,
        metadata=metadata,
    )


@router.post("/search", response_model=SigmaHQRulesListResponse)
async def search_rules(
    request: SigmaHQSearchRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    """Search SigmaHQ rules by keyword."""
    if not sigmahq_service.is_repo_cloned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SigmaHQ repository not cloned. Sync first.",
        )

    rules = sigmahq_service.search_rules(request.query, request.limit)
    return SigmaHQRulesListResponse(rules=rules, total=len(rules))


@router.post("/import", response_model=SigmaHQImportResponse)
async def import_rule(
    request: SigmaHQImportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SigmaHQImportResponse:
    """Import a SigmaHQ rule into CHAD."""
    if not sigmahq_service.is_repo_cloned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SigmaHQ repository not cloned. Sync first.",
        )

    content = sigmahq_service.get_rule_content(request.rule_path)

    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found in SigmaHQ repository",
        )

    # Parse rule metadata
    try:
        metadata = yaml.safe_load(content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse rule YAML: {str(e)}",
        )

    # Create the rule in CHAD
    rule = Rule(
        title=metadata.get("title", "Imported Rule"),
        description=metadata.get("description", f"Imported from SigmaHQ: {request.rule_path}"),
        yaml_content=content,
        severity=metadata.get("level", "medium"),
        status=RuleStatus.ENABLED,  # Start enabled but not deployed
        index_pattern_id=request.index_pattern_id,
        created_by=current_user.id,
        source=RuleSource.SIGMAHQ,
        sigmahq_path=request.rule_path,
    )
    db.add(rule)
    await db.flush()

    # Create initial version
    version = RuleVersion(
        rule_id=rule.id,
        version_number=1,
        yaml_content=content,
        changed_by=current_user.id,
    )
    db.add(version)

    await db.commit()
    await db.refresh(rule)

    return SigmaHQImportResponse(
        success=True,
        rule_id=str(rule.id),
        title=rule.title,
        message="Rule imported successfully. Review and deploy when ready.",
    )
