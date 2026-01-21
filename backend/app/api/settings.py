from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.services.opensearch import validate_opensearch_connection

router = APIRouter(prefix="/settings", tags=["settings"])


class OpenSearchConfig(BaseModel):
    host: str
    port: int = 9200
    username: str | None = None
    password: str | None = None
    use_ssl: bool = True


class OpenSearchTestResponse(BaseModel):
    success: bool
    steps: list[dict]


class OpenSearchStatusResponse(BaseModel):
    configured: bool


@router.post("/opensearch/test", response_model=OpenSearchTestResponse)
async def test_opensearch_connection(
    config: OpenSearchConfig,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Test OpenSearch connection with full CHAD capability validation."""
    result = validate_opensearch_connection(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
        use_ssl=config.use_ssl,
    )

    return OpenSearchTestResponse(
        success=result.success,
        steps=[
            {"name": step.name, "success": step.success, "error": step.error}
            for step in result.steps
        ],
    )


@router.post("/opensearch")
async def save_opensearch_config(
    config: OpenSearchConfig,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Save OpenSearch configuration after successful test."""
    # Check if settings already exist
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = result.scalar_one_or_none()

    config_value = {
        "host": config.host,
        "port": config.port,
        "username": config.username,
        "password": config.password,
        "use_ssl": config.use_ssl,
    }

    if setting:
        setting.value = config_value
    else:
        setting = Setting(key="opensearch", value=config_value)
        db.add(setting)

    await db.commit()

    return {"success": True}


@router.get("/opensearch/status", response_model=OpenSearchStatusResponse)
async def get_opensearch_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if OpenSearch is configured."""
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = result.scalar_one_or_none()

    return OpenSearchStatusResponse(configured=setting is not None)
