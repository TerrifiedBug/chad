from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.encryption import encrypt
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.services.audit import audit_log
from app.services.opensearch import validate_opensearch_connection
from app.services.settings import get_setting, set_setting
from app.services.webhooks import get_app_url_for_webhooks, send_webhook

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
    config: dict | None = None  # Config with masked password


class WebhookTestRequest(BaseModel):
    url: str
    provider: str = "generic"


class WebhookTestResponse(BaseModel):
    success: bool
    error: str | None = None


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


@router.post("/webhooks/test", response_model=WebhookTestResponse)
async def test_webhook(
    config: WebhookTestRequest,
    current_user: Annotated[User, Depends(require_admin)],
):
    """Test a webhook by sending a sample alert notification."""
    from datetime import datetime, timezone

    # Create a test alert payload
    test_alert_id = "test-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    test_alert = {
        "alert_id": test_alert_id,
        "rule_id": "test-rule",
        "rule_title": "Test Alert - CHAD Webhook Test",
        "severity": "informational",
        "status": "new",
        "tags": ["test", "webhook-verification"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Build alert URL if APP_URL is configured
    app_url = await get_app_url_for_webhooks()
    alert_url = f"{app_url}/alerts/{test_alert_id}" if app_url else None

    try:
        success = await send_webhook(
            url=config.url,
            provider=config.provider,
            alert=test_alert,
            timeout=15.0,
            alert_url=alert_url,
        )

        if success:
            return WebhookTestResponse(success=True)
        else:
            return WebhookTestResponse(
                success=False,
                error="Webhook returned an error response",
            )
    except Exception as e:
        return WebhookTestResponse(success=False, error=str(e))


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

    await audit_log(db, current_user.id, "settings.update", "settings", "opensearch", {"host": config.host, "port": config.port})
    await db.commit()

    return {"success": True}


@router.get("/opensearch/status", response_model=OpenSearchStatusResponse)
async def get_opensearch_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if OpenSearch is configured and return config (with masked password)."""
    result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = result.scalar_one_or_none()

    if setting is None:
        return OpenSearchStatusResponse(configured=False, config=None)

    # Return config with masked password
    config = dict(setting.value)
    if "password" in config:
        config["password"] = "********"

    return OpenSearchStatusResponse(configured=True, config=config)


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


# APP_URL endpoints - must be defined BEFORE the generic /{key} route
@router.get("/app-url")
async def get_app_url(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Get configured APP_URL."""
    setting = await get_setting(db, "app_url")
    return {"url": setting.get("url", "") if setting else ""}


@router.put("/app-url")
async def set_app_url(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Set APP_URL for SSO redirects and webhook links."""
    data = await request.json()
    url = data.get("url", "").strip().rstrip("/")

    if url and not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

    await set_setting(db, "app_url", {"url": url})
    await audit_log(db, current_user.id, "settings.update", "settings", "app_url", {"url": url})
    await db.commit()
    return {"success": True}


@router.put("/{key}")
async def update_setting(
    key: str,
    value: dict,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
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

    # For SSO settings, preserve existing encrypted client_secret if not provided
    # This allows enabling/disabling SSO without losing the secret
    if key == "sso" and setting and setting.value:
        existing_secret = setting.value.get("client_secret")
        if existing_secret and "client_secret" not in value:
            value["client_secret"] = existing_secret

    # Encrypt sensitive values
    encrypted_value = _encrypt_sensitive(key, value)

    if setting:
        setting.value = encrypted_value
    else:
        setting = Setting(key=key, value=encrypted_value)
        db.add(setting)

    # Log setting change without sensitive values
    masked_value = _mask_sensitive(key, value)
    await audit_log(db, current_user.id, "settings.update", "settings", key, {"value": masked_value})
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
