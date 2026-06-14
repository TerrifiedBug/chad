"""Multi-provider OIDC/SSO management API (manage_settings permission).

CRUD for ``sso_providers`` + their group mappings + a Test-Connection probe.
The client secret is write-only: it is encrypted at rest and never returned;
reads expose only a ``client_secret_set`` boolean.
"""

import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_permission_dep
from app.core.encryption import encrypt
from app.db.session import get_db
from app.models.sso_provider import SSOGroupMapping, SSOProvider
from app.models.user import User
from app.schemas.sso import (
    SSOProviderCreate,
    SSOProviderResponse,
    SSOProviderUpdate,
    SSOTestResult,
)
from app.services.audit import audit_log
from app.services.sso_providers import (
    build_provider_client,
    probe_oidc_discovery,
    validate_issuer_url,
)
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sso/providers", tags=["sso"])

_VALID_ROLES = {"admin", "analyst", "viewer"}
_VALID_TOKEN_AUTH = {"client_secret_post", "client_secret_basic", "none"}


def _to_response(provider: SSOProvider) -> SSOProviderResponse:
    resp = SSOProviderResponse.model_validate(provider)
    resp.client_secret_set = bool(provider.client_secret_encrypted)
    return resp


def _validate_issuer(issuer_url: str | None) -> str:
    """Validate + normalize the issuer URL (https + SSRF-safe) or HTTP 400."""
    try:
        return validate_issuer_url(issuer_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid issuer_url: {exc}",
        ) from exc


def _validate_enums(role: str | None, token_auth: str | None) -> None:
    if role is not None and role.lower() not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"default_role must be one of {sorted(_VALID_ROLES)}",
        )
    if token_auth is not None and token_auth not in _VALID_TOKEN_AUTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"token_auth_method must be one of {sorted(_VALID_TOKEN_AUTH)}",
        )


async def _load_provider(db: AsyncSession, provider_id: UUID) -> SSOProvider:
    result = await db.execute(
        select(SSOProvider)
        .options(selectinload(SSOProvider.group_mappings))
        .where(SSOProvider.id == provider_id)
    )
    provider = result.scalar_one_or_none()
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SSO provider not found"
        )
    return provider


def _apply_group_mappings(provider: SSOProvider, mappings) -> None:
    """Replace the provider's group mappings with the supplied set."""
    provider.group_mappings.clear()
    for m in mappings or []:
        role = (m.role or "viewer").lower()
        if role not in _VALID_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"group mapping role must be one of {sorted(_VALID_ROLES)}",
            )
        provider.group_mappings.append(
            SSOGroupMapping(
                group_value=m.group_value,
                team_id=m.team_id,
                role=role,
            )
        )


@router.get("", response_model=list[SSOProviderResponse])
async def list_providers(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    result = await db.execute(
        select(SSOProvider)
        .options(selectinload(SSOProvider.group_mappings))
        .order_by(SSOProvider.name)
    )
    return [_to_response(p) for p in result.scalars().all()]


@router.get("/{provider_id}", response_model=SSOProviderResponse)
async def get_provider(
    provider_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    return _to_response(await _load_provider(db, provider_id))


@router.post("", response_model=SSOProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    payload: SSOProviderCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    _validate_enums(payload.default_role, payload.token_auth_method)
    issuer_url = _validate_issuer(payload.issuer_url)

    provider = SSOProvider(
        name=payload.name,
        enabled=payload.enabled,
        issuer_url=issuer_url,
        client_id=payload.client_id,
        client_secret_encrypted=encrypt(payload.client_secret) if payload.client_secret else None,
        token_auth_method=payload.token_auth_method,
        scopes=payload.scopes,
        default_role=payload.default_role.lower(),
        default_team_id=payload.default_team_id,
        group_sync_enabled=payload.group_sync_enabled,
        groups_claim=payload.groups_claim,
        groups_scope=payload.groups_scope,
        role_claim=payload.role_claim,
        admin_values=payload.admin_values,
        analyst_values=payload.analyst_values,
        viewer_values=payload.viewer_values,
        require_email_verified=payload.require_email_verified,
    )
    _apply_group_mappings(provider, payload.group_mappings)
    db.add(provider)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An SSO provider with that name already exists",
        ) from exc

    await audit_log(
        db, current_user.id, "sso.provider_create", "sso_provider", str(provider.id),
        {"name": provider.name, "issuer_url": provider.issuer_url},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    provider = await _load_provider(db, provider.id)
    return _to_response(provider)


@router.put("/{provider_id}", response_model=SSOProviderResponse)
async def update_provider(
    provider_id: UUID,
    payload: SSOProviderUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    provider = await _load_provider(db, provider_id)
    _validate_enums(payload.default_role, payload.token_auth_method)

    data = payload.model_dump(exclude_unset=True)

    # Secret is write-only: only overwrite when a non-empty value is provided;
    # omitting it preserves the existing encrypted secret.
    if "client_secret" in data:
        secret = data.pop("client_secret")
        if secret:
            provider.client_secret_encrypted = encrypt(secret)

    if "group_mappings" in data:
        data.pop("group_mappings")
        _apply_group_mappings(provider, payload.group_mappings)

    if "issuer_url" in data and data["issuer_url"]:
        data["issuer_url"] = _validate_issuer(data["issuer_url"])
    if "default_role" in data and data["default_role"]:
        data["default_role"] = data["default_role"].lower()

    for field, value in data.items():
        setattr(provider, field, value)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An SSO provider with that name already exists",
        ) from exc

    await audit_log(
        db, current_user.id, "sso.provider_update", "sso_provider", str(provider.id),
        {"name": provider.name}, ip_address=get_client_ip(request),
    )
    await db.commit()
    provider = await _load_provider(db, provider.id)
    return _to_response(provider)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    provider = await _load_provider(db, provider_id)
    name = provider.name
    await db.delete(provider)
    await audit_log(
        db, current_user.id, "sso.provider_delete", "sso_provider", str(provider_id),
        {"name": name}, ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/{provider_id}/test", response_model=SSOTestResult)
async def test_provider_connection(
    provider_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Probe the provider's OIDC discovery document (SSRF-safe) and store the result."""
    provider = await _load_provider(db, provider_id)

    success, message, _doc = await probe_oidc_discovery(provider.issuer_url)

    tested_at = datetime.now(UTC)
    provider.last_tested_at = tested_at
    provider.last_test_success = success

    await audit_log(
        db, current_user.id, "sso.provider_test", "sso_provider", str(provider.id),
        {"success": success}, ip_address=get_client_ip(request),
    )
    await db.commit()

    # Warm the per-provider Authlib client on a successful probe so the next
    # login uses fresh settings. Best-effort: never fail the test on this.
    if success:
        try:
            build_provider_client(provider)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to warm SSO client for provider %s: %s", provider.id, exc)

    return SSOTestResult(success=success, message=message, last_tested_at=tested_at)
