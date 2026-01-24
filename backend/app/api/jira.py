"""Jira Cloud integration API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.encryption import encrypt
from app.db.session import get_db
from app.models.jira_config import JiraConfig
from app.models.user import User
from app.services.audit import audit_log
from app.services.jira import JiraAPIError, JiraService
from app.utils.request import get_client_ip

router = APIRouter(prefix="/jira", tags=["jira"])


# Request/Response models
class JiraConfigUpdate(BaseModel):
    """Request model for updating Jira configuration."""

    jira_url: str
    email: str
    api_token: str | None = None  # Optional on update if not changing
    default_project: str
    default_issue_type: str
    is_enabled: bool = True


class JiraConfigResponse(BaseModel):
    """Response model for Jira configuration."""

    id: str
    jira_url: str
    email: str
    default_project: str
    default_issue_type: str
    is_enabled: bool
    has_api_token: bool


class JiraConfigStatus(BaseModel):
    """Response for checking if Jira is configured."""

    configured: bool
    config: JiraConfigResponse | None = None


class JiraTestRequest(BaseModel):
    """Request model for testing Jira connection."""

    jira_url: str
    email: str
    api_token: str


class JiraTestResponse(BaseModel):
    """Response model for Jira connection test."""

    success: bool
    error: str | None = None
    server_title: str | None = None


class JiraProject(BaseModel):
    """Jira project info."""

    id: str
    key: str
    name: str


class JiraIssueType(BaseModel):
    """Jira issue type info."""

    id: str
    name: str
    description: str


@router.get("", response_model=JiraConfigStatus)
async def get_jira_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get current Jira configuration (admin only)."""
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config:
        return JiraConfigStatus(configured=False, config=None)

    return JiraConfigStatus(
        configured=True,
        config=JiraConfigResponse(
            id=str(config.id),
            jira_url=config.jira_url,
            email=config.email,
            default_project=config.default_project,
            default_issue_type=config.default_issue_type,
            is_enabled=config.is_enabled,
            has_api_token=bool(config.api_token_encrypted),
        ),
    )


@router.put("", response_model=JiraConfigResponse)
async def update_jira_config(
    data: JiraConfigUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Create or update Jira configuration (admin only)."""
    # Get existing config
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if config:
        # Update existing
        config.jira_url = data.jira_url
        config.email = data.email
        config.default_project = data.default_project
        config.default_issue_type = data.default_issue_type
        config.is_enabled = data.is_enabled

        # Only update token if provided
        if data.api_token:
            config.api_token_encrypted = encrypt(data.api_token)
    else:
        # Create new - token is required
        if not data.api_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="API token is required for initial configuration",
            )

        config = JiraConfig(
            jira_url=data.jira_url,
            email=data.email,
            api_token_encrypted=encrypt(data.api_token),
            default_project=data.default_project,
            default_issue_type=data.default_issue_type,
            is_enabled=data.is_enabled,
        )
        db.add(config)

    await audit_log(
        db,
        current_user.id,
        "jira.update",
        "jira_config",
        str(config.id) if config.id else "new",
        {"jira_url": data.jira_url, "email": data.email, "is_enabled": data.is_enabled},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    await db.refresh(config)

    return JiraConfigResponse(
        id=str(config.id),
        jira_url=config.jira_url,
        email=config.email,
        default_project=config.default_project,
        default_issue_type=config.default_issue_type,
        is_enabled=config.is_enabled,
        has_api_token=bool(config.api_token_encrypted),
    )


@router.delete("")
async def delete_jira_config(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Delete Jira configuration (admin only)."""
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jira configuration not found",
        )

    config_id = str(config.id)
    await db.delete(config)
    await audit_log(
        db,
        current_user.id,
        "jira.delete",
        "jira_config",
        config_id,
        {},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"success": True}


@router.post("/test", response_model=JiraTestResponse)
async def test_jira_connection(
    data: JiraTestRequest,
    _: Annotated[User, Depends(require_admin)],
):
    """Test Jira connection with provided credentials (admin only)."""
    # Create a temporary config for testing
    temp_config = JiraConfig(
        jira_url=data.jira_url,
        email=data.email,
        api_token_encrypted=encrypt(data.api_token),
        default_project="",
        default_issue_type="",
    )

    try:
        service = JiraService(temp_config)
        # Get server info to verify connection
        result = await service._make_request("GET", "/rest/api/3/serverInfo")
        return JiraTestResponse(
            success=True,
            server_title=result.get("serverTitle", "Jira Cloud"),
        )
    except JiraAPIError as e:
        return JiraTestResponse(success=False, error=e.message)
    except Exception as e:
        return JiraTestResponse(success=False, error=str(e))


@router.post("/test-saved", response_model=JiraTestResponse)
async def test_saved_jira_connection(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Test connection using saved Jira configuration (admin only)."""
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jira configuration not found",
        )

    try:
        service = JiraService(config)
        await service.test_connection()
        return JiraTestResponse(success=True)
    except JiraAPIError as e:
        return JiraTestResponse(success=False, error=e.message)
    except Exception as e:
        return JiraTestResponse(success=False, error=str(e))


@router.get("/projects", response_model=list[JiraProject])
async def get_jira_projects(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get available Jira projects (admin only)."""
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jira configuration not found",
        )

    try:
        service = JiraService(config)
        projects = await service.get_projects()
        return [JiraProject(**p) for p in projects]
    except JiraAPIError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Jira API error: {e.message}",
        )


@router.get("/issue-types/{project_key}", response_model=list[JiraIssueType])
async def get_jira_issue_types(
    project_key: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get available issue types for a Jira project (admin only)."""
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jira configuration not found",
        )

    try:
        service = JiraService(config)
        issue_types = await service.get_issue_types(project_key)
        return [JiraIssueType(**it) for it in issue_types]
    except JiraAPIError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Jira API error: {e.message}",
        )
