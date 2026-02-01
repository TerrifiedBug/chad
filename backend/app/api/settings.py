import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_permission_dep
from app.core.config import APP_VERSION
from app.core.encryption import decrypt, encrypt
from app.db.session import get_db
from app.models.setting import Setting
from app.models.user import User
from app.schemas.geoip import (
    GeoIPDownloadResponse,
    GeoIPSettings,
    GeoIPSettingsUpdate,
    GeoIPTestResponse,
)
from app.services.audit import audit_log
from app.services.geoip import geoip_service
from app.services.opensearch import validate_opensearch_connection
from app.services.settings import get_setting, set_setting
from app.services.webhooks import send_webhook
from app.utils.request import get_client_ip

router = APIRouter(prefix="/settings", tags=["settings"])


# Index pattern validation
ALLOWED_INDEX_PREFIXES = ["logs-", "alerts-", "events-", "sigma-"]
ALLOWED_INDEX_PATTERN = re.compile(r'^[a-z][a-z0-9_-]*\*?$')


def validate_index_pattern(pattern: str) -> tuple[bool, str]:
    """Validate index pattern is safe and within allowed prefixes.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not pattern:
        return False, "Pattern cannot be empty"

    # Block wildcard-only patterns
    if pattern in ("*", "*/*"):
        return False, "Wildcard-only patterns are not allowed"

    # Block path traversal attempts
    if "../" in pattern or "./" in pattern:
        return False, "Path traversal detected in pattern"

    # Check for allowed prefixes
    has_valid_prefix = any(
        pattern.startswith(prefix) or pattern.startswith(prefix.replace("-", "_"))
        for prefix in ALLOWED_INDEX_PREFIXES
    )

    if not has_valid_prefix:
        return False, f"Pattern must start with one of: {', '.join(ALLOWED_INDEX_PREFIXES)}"

    # Validate pattern format
    if not ALLOWED_INDEX_PATTERN.match(pattern.rstrip("*")):
        return False, "Pattern contains invalid characters"

    return True, ""


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
                "https://api.github.com/repos/TerrifiedBug/chad/releases/latest",
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
    verify_certs: bool = True  # Default to True for security - only disable for dev with self-signed certs


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
    last_tested: str | None = None
    last_test_success: bool | None = None


class AIStatusResponse(BaseModel):
    configured: bool
    provider: str | None = None


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
        verify_certs=config.verify_certs,
    )

    return OpenSearchTestResponse(
        success=result.success,
        steps=[
            {"name": step.name, "success": step.success, "error": step.error}
            for step in result.steps
        ],
    )


class IndexPatternTestRequest(BaseModel):
    pattern: str


class IndexPatternTestResponse(BaseModel):
    valid: bool
    pattern: str
    matching_indices: int | None = None
    indices: list[str] | None = None
    error: str | None = None


@router.post("/test-index-pattern", response_model=IndexPatternTestResponse)
async def test_index_pattern(
    data: IndexPatternTestRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Test OpenSearch index pattern with validation."""
    from app.api.deps import get_opensearch_client_optional

    # Validate pattern first
    is_valid, error_msg = validate_index_pattern(data.pattern)
    if not is_valid:
        return IndexPatternTestResponse(
            valid=False,
            pattern=data.pattern,
            error=error_msg,
        )

    # Get OpenSearch client and test
    opensearch_client = await get_opensearch_client_optional(db)
    if not opensearch_client:
        return IndexPatternTestResponse(
            valid=False,
            pattern=data.pattern,
            error="OpenSearch not configured",
        )

    try:
        # Test if pattern returns any indices
        response = opensearch_client.indices.get(index=data.pattern, ignore_unavailable=True)
        indices = list(response.keys()) if response else []

        return IndexPatternTestResponse(
            valid=True,
            pattern=data.pattern,
            matching_indices=len(indices),
            indices=indices[:10],  # Limit to first 10
        )
    except Exception as e:
        return IndexPatternTestResponse(
            valid=False,
            pattern=data.pattern,
            error=f"Pattern test failed: {str(e)}",
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
    from app.core.config import settings
    app_url = settings.APP_URL
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
    last_tested = ai_settings.get("last_tested")
    last_test_success = ai_settings.get("last_test_success")

    if provider == "disabled":
        return AITestResponse(
            success=False, provider="disabled", error="AI provider is disabled",
            last_tested=last_tested, last_test_success=last_test_success
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
                # Store last tested time
                now = datetime.now(UTC).isoformat()
                ai_settings["last_tested"] = now
                ai_settings["last_test_success"] = True
                await set_setting(db, "ai", ai_settings)
                await db.commit()
                return AITestResponse(success=True, provider=provider, model=model, last_tested=now)

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
                now = datetime.now(UTC).isoformat()
                ai_settings["last_tested"] = now
                ai_settings["last_test_success"] = True
                await set_setting(db, "ai", ai_settings)
                await db.commit()
                return AITestResponse(success=True, provider=provider, model=model, last_tested=now)

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
                now = datetime.now(UTC).isoformat()
                ai_settings["last_tested"] = now
                ai_settings["last_test_success"] = True
                await set_setting(db, "ai", ai_settings)
                await db.commit()
                return AITestResponse(success=True, provider=provider, model=model, last_tested=now)

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


@router.post("/ai/ping", response_model=AITestResponse)
async def ping_ai_connection(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """
    Lightweight AI connectivity check that doesn't consume tokens.
    Uses /v1/models for OpenAI and model listing for Anthropic.
    Suitable for scheduled background checks.
    """
    import httpx

    ai_settings = await get_setting(db, "ai")
    if not ai_settings:
        return AITestResponse(
            success=False, provider="none", error="AI settings not configured"
        )

    provider = ai_settings.get("ai_provider", "disabled")
    last_tested = ai_settings.get("last_tested")
    last_test_success = ai_settings.get("last_test_success")

    if provider == "disabled":
        return AITestResponse(
            success=False, provider="disabled", error="AI provider is disabled",
            last_tested=last_tested, last_test_success=last_test_success
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if provider == "ollama":
                # Ollama: Check /api/tags endpoint (lists models, no token cost)
                url = ai_settings.get("ai_ollama_url", "http://localhost:11434")
                response = await client.get(f"{url.rstrip('/')}/api/tags")
                response.raise_for_status()

            elif provider == "openai":
                # OpenAI: Use /v1/models endpoint (free, validates API key)
                api_key = ai_settings.get("ai_openai_key", "")
                if api_key:
                    try:
                        api_key = decrypt(api_key)
                    except Exception:
                        return AITestResponse(
                            success=False, provider=provider,
                            error="Failed to decrypt API key",
                            last_tested=last_tested, last_test_success=False
                        )
                if not api_key:
                    return AITestResponse(
                        success=False, provider=provider,
                        error="OpenAI API key not configured",
                        last_tested=last_tested, last_test_success=False
                    )
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                response.raise_for_status()

            elif provider == "anthropic":
                # Anthropic: No free endpoint, but we can validate key format
                # and make a request that fails fast if key is invalid
                api_key = ai_settings.get("ai_anthropic_key", "")
                if api_key:
                    try:
                        api_key = decrypt(api_key)
                    except Exception:
                        return AITestResponse(
                            success=False, provider=provider,
                            error="Failed to decrypt API key",
                            last_tested=last_tested, last_test_success=False
                        )
                if not api_key:
                    return AITestResponse(
                        success=False, provider=provider,
                        error="Anthropic API key not configured",
                        last_tested=last_tested, last_test_success=False
                    )
                # Use /v1/models endpoint - free, no token consumption
                response = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                )
                response.raise_for_status()

            else:
                return AITestResponse(
                    success=False, provider=provider, error=f"Unknown provider: {provider}"
                )

            # Update last tested time
            now = datetime.now(UTC).isoformat()
            ai_settings["last_tested"] = now
            ai_settings["last_test_success"] = True
            await set_setting(db, "ai", ai_settings)
            return AITestResponse(
                success=True, provider=provider,
                last_tested=now, last_test_success=True
            )

    except httpx.ConnectError as e:
        # Mark as failed
        now = datetime.now(UTC).isoformat()
        ai_settings["last_tested"] = now
        ai_settings["last_test_success"] = False
        await set_setting(db, "ai", ai_settings)
        return AITestResponse(
            success=False, provider=provider, error=f"Connection failed: {e}",
            last_tested=now, last_test_success=False
        )
    except httpx.HTTPStatusError as e:
        now = datetime.now(UTC).isoformat()
        ai_settings["last_tested"] = now
        ai_settings["last_test_success"] = False
        await set_setting(db, "ai", ai_settings)
        return AITestResponse(
            success=False, provider=provider,
            error=f"API error ({e.response.status_code})",
            last_tested=now, last_test_success=False
        )
    except Exception as e:
        now = datetime.now(UTC).isoformat()
        ai_settings["last_tested"] = now
        ai_settings["last_test_success"] = False
        await set_setting(db, "ai", ai_settings)
        return AITestResponse(
            success=False, provider=provider, error=f"Error: {str(e)}",
            last_tested=now, last_test_success=False
        )


@router.get("/ai/status", response_model=AIStatusResponse)
async def get_ai_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if AI is configured (has valid API key). Available to all authenticated users."""
    ai_settings = await get_setting(db, "ai")
    if not ai_settings:
        return AIStatusResponse(configured=False, provider=None)

    provider = ai_settings.get("ai_provider", "disabled")

    if provider == "disabled":
        return AIStatusResponse(configured=False, provider=None)

    if provider == "ollama":
        # Ollama just needs a URL, no API key required
        url = ai_settings.get("ai_ollama_url", "")
        configured = bool(url)
    elif provider == "openai":
        api_key = ai_settings.get("ai_openai_key", "")
        configured = bool(api_key)
    elif provider == "anthropic":
        api_key = ai_settings.get("ai_anthropic_key", "")
        configured = bool(api_key)
    else:
        configured = False

    return AIStatusResponse(
        configured=configured,
        provider=provider if configured else None
    )


@router.post("/opensearch")
async def save_opensearch_config(
    config: OpenSearchConfig,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
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
        "verify_certs": config.verify_certs,  # Save SSL verification preference
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


# Security settings models
class SecuritySettings(BaseModel):
    force_2fa_on_signup: bool = False


class SecuritySettingsResponse(BaseModel):
    force_2fa_on_signup: bool


# Security settings endpoints
@router.get("/security", response_model=SecuritySettingsResponse)
async def get_security_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get security settings."""
    security = await get_setting(db, "security")
    return SecuritySettingsResponse(
        force_2fa_on_signup=security.get("force_2fa_on_signup", False) if security else False
    )


@router.put("/security", response_model=SecuritySettingsResponse)
async def update_security_settings(
    data: SecuritySettings,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Update security settings."""
    security = await get_setting(db, "security") or {}
    security["force_2fa_on_signup"] = data.force_2fa_on_signup
    await set_setting(db, "security", security)
    await audit_log(
        db, current_user.id, "settings.update", "settings", "security",
        {"force_2fa_on_signup": data.force_2fa_on_signup},
        ip_address=get_client_ip(request)
    )
    await db.commit()
    return SecuritySettingsResponse(force_2fa_on_signup=data.force_2fa_on_signup)


# GeoIP endpoints
@router.get("/geoip", response_model=GeoIPSettings)
async def get_geoip_settings(
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get GeoIP enrichment settings."""
    geoip_settings = await get_setting(db, "geoip")
    license_key = geoip_settings.get("license_key") if geoip_settings else None
    enabled = geoip_settings.get("enabled", False) if geoip_settings else False
    update_interval = geoip_settings.get("update_interval", "weekly") if geoip_settings else "weekly"

    return GeoIPSettings(
        enabled=enabled,
        has_license_key=bool(license_key),
        database_available=geoip_service.is_database_available(),
        database_info=geoip_service.get_database_info(),
        update_interval=update_interval,
    )


@router.put("/geoip", response_model=GeoIPSettings)
async def update_geoip_settings(
    data: GeoIPSettingsUpdate,
    request: Request,
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update GeoIP enrichment settings."""
    geoip_settings = await get_setting(db, "geoip") or {}

    if data.license_key is not None:
        geoip_settings["license_key"] = encrypt(data.license_key)
    if data.update_interval is not None:
        geoip_settings["update_interval"] = data.update_interval
    if data.enabled is not None:
        geoip_settings["enabled"] = data.enabled

    await set_setting(db, "geoip", geoip_settings)
    await audit_log(
        db, _.id, "settings.update", "settings", "geoip",
        {"enabled": geoip_settings.get("enabled"), "update_interval": geoip_settings.get("update_interval")},
        ip_address=get_client_ip(request)
    )

    return await get_geoip_settings(_, db)


@router.post("/geoip/download", response_model=GeoIPDownloadResponse)
async def download_geoip_database(
    request: Request,
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Download/update the GeoIP database."""
    geoip_settings = await get_setting(db, "geoip")
    if not geoip_settings or not geoip_settings.get("license_key"):
        raise HTTPException(status_code=400, detail="License key not configured")

    try:
        license_key = decrypt(geoip_settings["license_key"])
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt license key")

    result = await geoip_service.download_database(license_key)

    if result["success"]:
        # Save last update timestamp (for health monitoring)
        if result.get("info") and result["info"].get("modified_at"):
            await set_setting(db, "geoip_last_update", result["info"]["modified_at"])

        await audit_log(
            db, _.id, "geoip.download", "settings", "geoip",
            {"success": True},
            ip_address=get_client_ip(request)
        )
        await db.commit()

    return GeoIPDownloadResponse(**result)


@router.post("/geoip/test", response_model=GeoIPTestResponse)
async def test_geoip_lookup(
    ip: str,
    _: Annotated[User, Depends(require_admin)],
):
    """Test GeoIP lookup for an IP address."""
    if not geoip_service.is_database_available():
        raise HTTPException(status_code=400, detail="GeoIP database not available")

    result = geoip_service.lookup(ip)
    return GeoIPTestResponse(
        ip=ip,
        is_public=geoip_service.is_public_ip(ip),
        geo=result,
    )


# Version cleanup settings models
class VersionCleanupSettings(BaseModel):
    enabled: bool = True
    min_keep: int = 10
    max_age_days: int = 90


class VersionCleanupSettingsResponse(BaseModel):
    enabled: bool
    min_keep: int
    max_age_days: int


@router.get("/version-cleanup", response_model=VersionCleanupSettingsResponse)
async def get_version_cleanup_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get version cleanup settings."""
    cleanup = await get_setting(db, "version_cleanup")
    return VersionCleanupSettingsResponse(
        enabled=cleanup.get("enabled", True) if cleanup else True,
        min_keep=cleanup.get("min_keep", 10) if cleanup else 10,
        max_age_days=cleanup.get("max_age_days", 90) if cleanup else 90,
    )


@router.put("/version-cleanup", response_model=VersionCleanupSettingsResponse)
async def update_version_cleanup_settings(
    data: VersionCleanupSettings,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Update version cleanup settings."""
    # Validate values
    if data.min_keep < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="min_keep must be at least 1"
        )
    if data.max_age_days < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="max_age_days must be at least 1"
        )

    cleanup = {
        "enabled": data.enabled,
        "min_keep": data.min_keep,
        "max_age_days": data.max_age_days,
    }
    await set_setting(db, "version_cleanup", cleanup)
    await audit_log(
        db, current_user.id, "settings.update", "settings", "version_cleanup",
        cleanup,
        ip_address=get_client_ip(request)
    )
    await db.commit()
    return VersionCleanupSettingsResponse(**cleanup)


# Alert Clustering Settings
class AlertClusteringSettings(BaseModel):
    """Alert clustering configuration settings."""

    enabled: bool = False
    window_minutes: int = Field(default=60, ge=1, le=1440)


class AlertClusteringSettingsResponse(BaseModel):
    """Response model for alert clustering settings."""

    enabled: bool
    window_minutes: int


@router.get("/alert-clustering", response_model=AlertClusteringSettingsResponse)
async def get_alert_clustering_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    """Get alert clustering settings."""
    settings_data = await get_setting(db, "alert_clustering")
    if not settings_data:
        # Return defaults
        return AlertClusteringSettingsResponse(
            enabled=False,
            window_minutes=60,
        )
    return AlertClusteringSettingsResponse(
        enabled=settings_data.get("enabled", False),
        window_minutes=settings_data.get("window_minutes", 60),
    )


@router.put("/alert-clustering", response_model=AlertClusteringSettingsResponse)
async def update_alert_clustering_settings(
    data: AlertClusteringSettings,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Update alert clustering settings (admin only)."""
    settings_value = {
        "enabled": data.enabled,
        "window_minutes": data.window_minutes,
    }
    await set_setting(db, "alert_clustering", settings_value)
    await audit_log(
        db,
        current_user.id,
        "settings.update",
        "settings",
        "alert_clustering",
        settings_value,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return AlertClusteringSettingsResponse(**settings_value)


@router.put("/{key}")
async def update_setting(
    key: str,
    value: dict,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
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
    # Track which fields are already encrypted (to avoid double-encryption)
    already_encrypted_fields: set[str] = set()
    if key == "sso" and setting and setting.value:
        existing_secret = setting.value.get("client_secret")
        if existing_secret and "client_secret" not in value:
            value["client_secret"] = existing_secret
            # Mark as already encrypted to prevent double-encryption
            already_encrypted_fields.add("client_secret")

    # Encrypt sensitive values (skip already-encrypted fields)
    encrypted_value = _encrypt_sensitive(key, value, skip_fields=already_encrypted_fields)

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


def _encrypt_sensitive(key: str, value: dict, skip_fields: set[str] | None = None) -> dict:
    """Encrypt sensitive fields in settings value.

    Args:
        key: The setting key (unused but kept for future use)
        value: The settings dict to encrypt
        skip_fields: Fields to skip encryption for (already encrypted)
    """
    if not isinstance(value, dict):
        return value

    skip_fields = skip_fields or set()

    # Patterns to match in field names (substring match)
    sensitive_patterns = {"password", "secret", "token", "api_key", "client_secret"}
    # Specific field names that should be encrypted
    sensitive_exact = {"ai_openai_key", "ai_anthropic_key"}
    result = {}

    for k, v in value.items():
        # Skip fields that are already encrypted
        if k in skip_fields:
            result[k] = v
            continue

        is_sensitive = (
            k.lower() in sensitive_exact
            or any(s in k.lower() for s in sensitive_patterns)
        )
        if is_sensitive and v and isinstance(v, str):
            result[k] = encrypt(v)
        else:
            result[k] = v

    return result
