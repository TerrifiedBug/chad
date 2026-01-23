from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.config import APP_VERSION
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.services.audit import audit_log
from app.services.opensearch import validate_opensearch_connection
from app.services.settings import get_setting, set_setting
from app.services.webhooks import get_app_url_for_webhooks, send_webhook
from app.utils.request import get_client_ip

router = APIRouter(prefix="/settings", tags=["settings"])


# Version response models
class VersionResponse(BaseModel):
    version: str


class UpdateCheckResponse(BaseModel):
    current: str
    latest: str | None
    update_available: bool
    release_url: str | None = None


@router.get("/version", response_model=VersionResponse)
async def get_version():
    """Get current application version."""
    return VersionResponse(version=APP_VERSION)


@router.get("/version/check", response_model=UpdateCheckResponse)
async def check_for_updates():
    """Check GitHub for latest version."""
    import httpx

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/repos/YOUR_ORG/chad/releases/latest",
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                latest = data.get("tag_name", "").lstrip("v")
                # Simple version comparison - check if different and latest is "greater"
                update_available = False
                if latest and latest != APP_VERSION:
                    # Basic semver comparison (works for most cases)
                    try:
                        current_parts = [int(x) for x in APP_VERSION.split("-")[0].split(".")]
                        latest_parts = [int(x) for x in latest.split("-")[0].split(".")]
                        # Pad to same length
                        while len(current_parts) < 3:
                            current_parts.append(0)
                        while len(latest_parts) < 3:
                            latest_parts.append(0)
                        update_available = latest_parts > current_parts
                    except (ValueError, AttributeError):
                        # If parsing fails, just check if they're different
                        update_available = latest != APP_VERSION
                return UpdateCheckResponse(
                    current=APP_VERSION,
                    latest=latest,
                    update_available=update_available,
                    release_url=data.get("html_url"),
                )
    except Exception:
        pass

    return UpdateCheckResponse(
        current=APP_VERSION,
        latest=None,
        update_available=False,
    )


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


class AITestResponse(BaseModel):
    success: bool
    provider: str
    model: str | None = None
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
    from datetime import datetime

    # Create a test alert payload
    test_alert_id = "test-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    test_alert = {
        "alert_id": test_alert_id,
        "rule_id": "test-rule",
        "rule_title": "Test Alert - CHAD Webhook Test",
        "severity": "informational",
        "status": "new",
        "tags": ["test", "webhook-verification"],
        "created_at": datetime.now(UTC).isoformat(),
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


@router.post("/ai/test", response_model=AITestResponse)
async def test_ai_connection(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """Test AI provider connection with a simple request."""
    import json as json_module

    import httpx

    ai_settings = await get_setting(db, "ai")
    if not ai_settings:
        return AITestResponse(
            success=False, provider="none", error="AI settings not configured"
        )

    provider = ai_settings.get("ai_provider", "disabled")
    if provider == "disabled":
        return AITestResponse(
            success=False, provider="disabled", error="AI provider is disabled"
        )

    test_prompt = "Respond with only the word 'OK' to confirm connectivity."

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if provider == "ollama":
                url = ai_settings.get("ai_ollama_url", "http://localhost:11434")
                model = ai_settings.get("ai_ollama_model", "llama3")
                response = await client.post(
                    f"{url.rstrip('/')}/api/generate",
                    json={"model": model, "prompt": test_prompt, "stream": False},
                )
                response.raise_for_status()
                return AITestResponse(success=True, provider=provider, model=model)

            elif provider == "openai":
                api_key = ai_settings.get("ai_openai_key", "")
                if api_key:
                    try:
                        api_key = decrypt(api_key)
                    except Exception:
                        return AITestResponse(
                            success=False,
                            provider=provider,
                            error="Failed to decrypt API key. Please re-enter it.",
                        )
                if not api_key:
                    return AITestResponse(
                        success=False,
                        provider=provider,
                        error="OpenAI API key not configured",
                    )
                model = ai_settings.get("ai_openai_model", "gpt-4o")
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": test_prompt}],
                        "max_tokens": 10,
                    },
                )
                response.raise_for_status()
                return AITestResponse(success=True, provider=provider, model=model)

            elif provider == "anthropic":
                api_key = ai_settings.get("ai_anthropic_key", "")
                if api_key:
                    try:
                        api_key = decrypt(api_key)
                    except Exception:
                        return AITestResponse(
                            success=False,
                            provider=provider,
                            error="Failed to decrypt API key. Please re-enter it.",
                        )
                if not api_key:
                    return AITestResponse(
                        success=False,
                        provider=provider,
                        error="Anthropic API key not configured",
                    )
                model = ai_settings.get("ai_anthropic_model", "claude-sonnet-4-20250514")
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": model,
                        "max_tokens": 10,
                        "messages": [{"role": "user", "content": test_prompt}],
                    },
                )
                response.raise_for_status()
                return AITestResponse(success=True, provider=provider, model=model)

            else:
                return AITestResponse(
                    success=False,
                    provider=provider,
                    error=f"Unknown provider: {provider}",
                )

    except httpx.ConnectError as e:
        return AITestResponse(
            success=False, provider=provider, error=f"Connection failed: {e}"
        )
    except httpx.HTTPStatusError as e:
        # Try to extract a useful error message from the response
        error_detail = ""
        try:
            error_json = e.response.json()
            if "error" in error_json:
                if isinstance(error_json["error"], dict):
                    error_detail = error_json["error"].get("message", str(error_json["error"]))
                else:
                    error_detail = str(error_json["error"])
            elif "message" in error_json:
                error_detail = error_json["message"]
            else:
                error_detail = e.response.text[:200]
        except (json_module.JSONDecodeError, ValueError):
            error_detail = e.response.text[:200] if e.response.text else "No response body"

        return AITestResponse(
            success=False,
            provider=provider,
            error=f"API error ({e.response.status_code}): {error_detail}",
        )
    except Exception as e:
        return AITestResponse(
            success=False, provider=provider, error=f"Error: {str(e)}"
        )


@router.post("/opensearch")
async def save_opensearch_config(
    config: OpenSearchConfig,
    request: Request,
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

    await audit_log(db, current_user.id, "settings.update", "settings", "opensearch", {"host": config.host, "port": config.port}, ip_address=get_client_ip(request))
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
    await audit_log(db, current_user.id, "settings.update", "settings", "app_url", {"url": url}, ip_address=get_client_ip(request))
    await db.commit()
    return {"success": True}


@router.put("/{key}")
async def update_setting(
    key: str,
    value: dict,
    request: Request,
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
    await audit_log(db, current_user.id, "settings.update", "settings", key, {"value": masked_value}, ip_address=get_client_ip(request))
    await db.commit()
    return {"success": True}


def _mask_sensitive(key: str, value: dict | None) -> dict | None:
    """Mask sensitive values in settings."""
    if value is None:
        return None

    # Patterns to match in field names (substring match)
    sensitive_patterns = {"password", "secret", "token", "api_key", "client_secret"}
    # Specific field names that should be masked
    sensitive_exact = {"ai_openai_key", "ai_anthropic_key"}

    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            is_sensitive = (
                k.lower() in sensitive_exact
                or any(s in k.lower() for s in sensitive_patterns)
            )
            result[k] = "********" if is_sensitive and v else v
        return result
    return value


def _encrypt_sensitive(key: str, value: dict) -> dict:
    """Encrypt sensitive fields in settings value."""
    if not isinstance(value, dict):
        return value

    # Patterns to match in field names (substring match)
    sensitive_patterns = {"password", "secret", "token", "api_key", "client_secret"}
    # Specific field names that should be encrypted
    sensitive_exact = {"ai_openai_key", "ai_anthropic_key"}
    result = {}

    for k, v in value.items():
        is_sensitive = (
            k.lower() in sensitive_exact
            or any(s in k.lower() for s in sensitive_patterns)
        )
        if is_sensitive and v and isinstance(v, str):
            result[k] = encrypt(v)
        else:
            result[k] = v

    return result
