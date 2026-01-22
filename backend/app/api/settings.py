from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.encryption import encrypt
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

    # Encrypt password before storing
    encrypted_password = encrypt(config.password) if config.password else None

    config_value = {
        "host": config.host,
        "port": config.port,
        "username": config.username,
        "password": encrypted_password,
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


# General settings endpoints
@router.get("")
async def list_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get all configurable settings (admin only)."""
    result = await db.execute(select(Setting))
    settings = result.scalars().all()

    # Convert to dict, hiding sensitive values
    return {s.key: _mask_sensitive(s.key, s.value) for s in settings}


@router.put("/{key}")
async def update_setting(
    key: str,
    value: dict,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Update a setting (admin only)."""
    # Don't allow updating opensearch via this endpoint (use dedicated endpoint)
    if key == "opensearch":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /settings/opensearch endpoint to update OpenSearch config",
        )

    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()

    # Encrypt sensitive values
    encrypted_value = _encrypt_sensitive(key, value)

    if setting:
        setting.value = encrypted_value
    else:
        setting = Setting(key=key, value=encrypted_value)
        db.add(setting)

    await db.commit()
    return {"success": True}


def _mask_sensitive(key: str, value: dict | None) -> dict | None:
    """Mask sensitive values in settings."""
    if value is None:
        return None

    sensitive_keys = {"password", "secret", "token", "api_key", "client_secret"}
    if isinstance(value, dict):
        return {
            k: "********" if any(s in k.lower() for s in sensitive_keys) else v
            for k, v in value.items()
        }
    return value


def _encrypt_sensitive(key: str, value: dict) -> dict:
    """Encrypt sensitive fields in settings value."""
    if not isinstance(value, dict):
        return value

    sensitive_fields = {"password", "secret", "token", "api_key", "client_secret"}
    result = {}

    for k, v in value.items():
        if any(s in k.lower() for s in sensitive_fields) and v and isinstance(v, str):
            result[k] = encrypt(v)
        else:
            result[k] = v

    return result
