"""SCIM 2.0 Users provisioning API (RFC 7643/7644).

Mounted at ``/api/scim/v2``. Bearer-authenticated (constant-time), disabled by
default. SCIM-created users are marked ``provisioned_via=scim`` + a unique
``scim_external_id``. Coexistence guards stop SCIM from ever deactivating a
LOCAL/SSO user or the last active admin.

Single-tenant: no Host->org resolution. CSRF middleware exempts ``/api/scim/``.
"""

import logging
import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission_dep
from app.db.session import get_db
from app.models.user import ProvisionedVia, User, UserRole
from app.services.audit import audit_log
from app.services.scim import (
    can_scim_deactivate,
    generate_scim_token,
    get_scim_config,
    get_scim_token_plaintext,
    is_scim_enabled,
    set_scim_enabled,
    verify_scim_token,
)
from app.services.system_log import LogCategory, system_log_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scim", tags=["scim"])

SCIM_CONTENT_TYPE = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SPC_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

# Map SCIM roles to CHAD roles for entitlements (best-effort; default viewer).
_DEFAULT_SCIM_ROLE = UserRole.VIEWER


def _scim_error(detail: str, status_code: int, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [ERROR_SCHEMA],
        "detail": detail,
        "status": str(status_code),
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(
        status_code=status_code, content=body, media_type=SCIM_CONTENT_TYPE
    )


def _user_to_scim(user: User, request: Request) -> dict[str, Any]:
    location = str(request.url_for("scim_get_user", user_id=str(user.id)))
    return {
        "schemas": [USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.scim_external_id,
        "userName": user.email,
        "name": {"formatted": user.email},
        "emails": [{"value": user.email, "primary": True}],
        "active": user.is_active,
        "meta": {
            "resourceType": "User",
            "location": location,
            "created": user.created_at.isoformat() if user.created_at else None,
            "lastModified": user.updated_at.isoformat() if user.updated_at else None,
        },
    }


def _scim_response(content: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content=content, media_type=SCIM_CONTENT_TYPE
    )


def _normalize_email(value: str | None) -> str | None:
    """Lowercase + strip an email (mirror the local-login path) or None."""
    if not value:
        return None
    normalized = str(value).strip().lower()
    return normalized or None


def _extract_username(payload: dict) -> str | None:
    """Extract the email/userName from a SCIM User payload (lowercase-normalized)."""
    username = payload.get("userName")
    if username:
        return _normalize_email(username)
    emails = payload.get("emails")
    if isinstance(emails, list) and emails:
        primary = next((e for e in emails if e.get("primary")), emails[0])
        if isinstance(primary, dict) and primary.get("value"):
            return _normalize_email(primary["value"])
    return None


async def _email_rename_conflict(
    db: AsyncSession, new_email: str, user: User
) -> bool:
    """Whether renaming ``user`` onto ``new_email`` would collide with another
    account (re-runs the create-path coexistence check on PUT/PATCH renames).

    Refuses if the target email already belongs to a DIFFERENT user — most
    importantly a non-SCIM (LOCAL/SSO) account, which SCIM must never seize.
    """
    if new_email == user.email:
        return False
    existing = (
        await db.execute(select(User).where(User.email == new_email))
    ).scalar_one_or_none()
    return existing is not None and existing.id != user.id


# SCIM filter: ``attr eq "value"`` (the only operator we support — filter=true,
# userName/externalId eq per the spec scope).
_FILTER_RE = re.compile(
    r'^\s*(?P<attr>\w+)\s+eq\s+"(?P<value>[^"]*)"\s*$', re.IGNORECASE
)


def _parse_eq_filter(filter_str: str) -> tuple[str, str] | None:
    m = _FILTER_RE.match(filter_str or "")
    if not m:
        return None
    return m.group("attr").lower(), m.group("value")


async def authenticate_scim(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> bool:
    """SCIM bearer auth dependency.

    - SCIM disabled  -> 403 (no info leak about token validity).
    - Missing/!Bearer-> 401.
    - Wrong token    -> 401 (constant-time compare).
    Raises a SCIM-shaped error via a sentinel exception on failure.
    """
    if not await is_scim_enabled(db):
        raise _ScimAuthError(_scim_error("SCIM is not enabled", status.HTTP_403_FORBIDDEN))

    if not authorization or not authorization.startswith("Bearer "):
        raise _ScimAuthError(
            _scim_error("Missing or invalid Authorization header", status.HTTP_401_UNAUTHORIZED)
        )

    provided = authorization[len("Bearer "):].strip()
    expected = await get_scim_token_plaintext(db)
    if not verify_scim_token(provided, expected):
        raise _ScimAuthError(_scim_error("Invalid bearer token", status.HTTP_401_UNAUTHORIZED))

    return True


class _ScimAuthError(Exception):
    """Carries a pre-built SCIM JSONResponse out of the auth dependency."""

    def __init__(self, response: JSONResponse):
        self.response = response


async def _commit_or_500(db: AsyncSession, operation: str) -> JSONResponse | None:
    """Commit the SCIM mutation; on a genuine failure log scim_sync_failed.

    Returns a SCIM 500 JSONResponse on failure (and rolls back), or None on
    success. Policy refusals (403/409) never reach here, so they never raise a
    sync-failure system log.
    """
    try:
        await db.commit()
        return None
    except Exception as exc:  # pragma: no cover - genuine infra failure
        await db.rollback()
        logger.exception("SCIM %s failed", operation)
        try:
            await system_log_service.log_error(
                db,
                category=LogCategory.INTEGRATIONS,
                service="scim",
                message=f"SCIM sync failed during {operation}",
                details={"error": str(exc)},
            )
            await db.commit()
        except Exception:
            await db.rollback()
        return _scim_error(
            "Internal error processing SCIM request",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def _get_scim_user(db: AsyncSession, user_id: str) -> User | None:
    try:
        uid = uuid.UUID(str(user_id))
    except (ValueError, TypeError):
        return None
    result = await db.execute(select(User).where(User.id == uid))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# ServiceProviderConfig
# ---------------------------------------------------------------------------
@router.get("/v2/ServiceProviderConfig")
async def scim_service_provider_config(
    request: Request,
    _: Annotated[bool, Depends(authenticate_scim)],
):
    return _scim_response(
        {
            "schemas": [SPC_SCHEMA],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication via a bearer token.",
                    "primary": True,
                }
            ],
            "meta": {"resourceType": "ServiceProviderConfig"},
        }
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
# RFC 7644 §3.4.2.4 — cap how many resources a single page may return.
SCIM_MAX_RESULTS = 200


@router.get("/v2/Users")
async def scim_list_users(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
):
    stmt = select(User)

    if filter:
        parsed = _parse_eq_filter(filter)
        if parsed is None:
            return _scim_error(
                "Unsupported filter. Only 'attr eq \"value\"' is supported.",
                status.HTTP_400_BAD_REQUEST,
                scim_type="invalidFilter",
            )
        attr, value = parsed
        if attr == "username":
            stmt = stmt.where(User.email == value)
        elif attr == "externalid":
            stmt = stmt.where(User.scim_external_id == value)
        else:
            return _scim_error(
                f"Filtering on '{attr}' is not supported.",
                status.HTTP_400_BAD_REQUEST,
                scim_type="invalidFilter",
            )

    # Clamp paging to the advertised maximum and push LIMIT/OFFSET into SQL so we
    # never materialize the whole users table to slice it in memory.
    start = max(startIndex, 1)
    limit = max(min(count, SCIM_MAX_RESULTS), 0)
    offset = start - 1

    total = (
        await db.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar() or 0

    result = await db.execute(
        stmt.order_by(User.email).offset(offset).limit(limit)
    )
    page = list(result.scalars().all())

    return _scim_response(
        {
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(page),
            "Resources": [_user_to_scim(u, request) for u in page],
        }
    )


@router.get("/v2/Users/{user_id}", name="scim_get_user")
async def scim_get_user(
    user_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
):
    user = await _get_scim_user(db, user_id)
    if user is None:
        return _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    return _scim_response(_user_to_scim(user, request))


@router.post("/v2/Users")
async def scim_create_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
):
    payload = await request.json()
    username = _extract_username(payload)
    if not username:
        return _scim_error(
            "userName is required", status.HTTP_400_BAD_REQUEST, scim_type="invalidValue"
        )

    external_id = payload.get("externalId")
    active = payload.get("active", True)

    # If a user with this email already exists, SCIM must not silently take it
    # over (coexistence): conflict unless it is already the same SCIM resource.
    existing = (
        await db.execute(select(User).where(User.email == username))
    ).scalar_one_or_none()
    if existing is not None:
        if existing.provisioned_via == ProvisionedVia.SCIM.value:
            return _scim_error(
                "User already exists", status.HTTP_409_CONFLICT, scim_type="uniqueness"
            )
        return _scim_error(
            "A non-SCIM user with this userName already exists",
            status.HTTP_409_CONFLICT,
            scim_type="uniqueness",
        )

    user = User(
        email=username,
        password_hash=None,
        role=_DEFAULT_SCIM_ROLE,
        is_active=bool(active),
        provisioned_via=ProvisionedVia.SCIM.value,
        scim_external_id=str(external_id) if external_id else None,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return _scim_error(
            "User already exists", status.HTTP_409_CONFLICT, scim_type="uniqueness"
        )

    await audit_log(
        db, None, "scim.user_create", "user", str(user.id),
        {"userName": user.email, "externalId": user.scim_external_id},
        ip_address=get_client_ip(request),
    )
    err = await _commit_or_500(db, "create")
    if err is not None:
        return err
    await db.refresh(user)
    return _scim_response(_user_to_scim(user, request), status.HTTP_201_CREATED)


@router.put("/v2/Users/{user_id}")
async def scim_replace_user(
    user_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
):
    user = await _get_scim_user(db, user_id)
    if user is None:
        return _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    if user.provisioned_via != ProvisionedVia.SCIM.value:
        return _scim_error(
            "User is not SCIM-provisioned and cannot be modified via SCIM",
            status.HTTP_403_FORBIDDEN,
            scim_type="mutability",
        )

    payload = await request.json()
    desired_active = bool(payload.get("active", user.is_active))

    # Deactivation goes through the coexistence guard (last-admin protection).
    if user.is_active and not desired_active:
        allowed, reason = await can_scim_deactivate(db, user)
        if not allowed:
            await db.rollback()
            return _scim_error(reason, status.HTTP_403_FORBIDDEN, scim_type="mutability")

    new_username = _extract_username(payload)
    if new_username and new_username != user.email:
        # Coexistence: never rename a SCIM user onto another account's email
        # (especially a LOCAL/SSO user) — that would be a takeover by rename.
        if await _email_rename_conflict(db, new_username, user):
            await db.rollback()
            return _scim_error(
                "userName is already in use by another account",
                status.HTTP_409_CONFLICT,
                scim_type="uniqueness",
            )
        user.email = new_username
    if "externalId" in payload:
        user.scim_external_id = (
            str(payload["externalId"]) if payload["externalId"] else None
        )
    user.is_active = desired_active

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return _scim_error(
            "userName or externalId already in use",
            status.HTTP_409_CONFLICT,
            scim_type="uniqueness",
        )

    await audit_log(
        db, None, "scim.user_replace", "user", str(user.id),
        {"userName": user.email, "active": user.is_active},
        ip_address=get_client_ip(request),
    )
    err = await _commit_or_500(db, "replace")
    if err is not None:
        return err
    await db.refresh(user)
    return _scim_response(_user_to_scim(user, request))


@router.patch("/v2/Users/{user_id}")
async def scim_patch_user(
    user_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
):
    user = await _get_scim_user(db, user_id)
    if user is None:
        return _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    if user.provisioned_via != ProvisionedVia.SCIM.value:
        return _scim_error(
            "User is not SCIM-provisioned and cannot be modified via SCIM",
            status.HTTP_403_FORBIDDEN,
            scim_type="mutability",
        )

    payload = await request.json()
    operations = payload.get("Operations") or payload.get("operations") or []
    if not isinstance(operations, list):
        return _scim_error(
            "Operations must be a list", status.HTTP_400_BAD_REQUEST, scim_type="invalidSyntax"
        )

    desired_active = user.is_active
    new_external_id = user.scim_external_id
    new_email = user.email

    for op in operations:
        if not isinstance(op, dict):
            continue
        # RFC 7644: op names are case-insensitive.
        action = str(op.get("op", "")).lower()
        path = str(op.get("path", "")).lower().strip()
        value = op.get("value")

        if action == "remove" and path == "active":
            desired_active = False
            continue
        if action not in ("replace", "add"):
            continue

        # value may be a scalar (with path) or a dict of attrs (no/implicit path).
        if path == "active":
            desired_active = _coerce_bool(value)
        elif path == "externalid":
            new_external_id = str(value) if value else None
        elif path in ("username", "emails", "emails[primary eq true].value"):
            if isinstance(value, str):
                new_email = _normalize_email(value) or new_email
        elif not path and isinstance(value, dict):
            if "active" in value:
                desired_active = _coerce_bool(value["active"])
            if "externalId" in value:
                new_external_id = str(value["externalId"]) if value["externalId"] else None
            if "userName" in value:
                new_email = _normalize_email(value["userName"]) or new_email

    # Deactivation guard.
    if user.is_active and not desired_active:
        allowed, reason = await can_scim_deactivate(db, user)
        if not allowed:
            await db.rollback()
            return _scim_error(reason, status.HTTP_403_FORBIDDEN, scim_type="mutability")

    # Rename coexistence: never rename onto another account's email.
    if new_email != user.email and await _email_rename_conflict(db, new_email, user):
        await db.rollback()
        return _scim_error(
            "userName is already in use by another account",
            status.HTTP_409_CONFLICT,
            scim_type="uniqueness",
        )

    user.is_active = desired_active
    user.scim_external_id = new_external_id
    user.email = new_email

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return _scim_error(
            "userName or externalId already in use",
            status.HTTP_409_CONFLICT,
            scim_type="uniqueness",
        )

    await audit_log(
        db, None, "scim.user_patch", "user", str(user.id),
        {"active": user.is_active}, ip_address=get_client_ip(request),
    )
    err = await _commit_or_500(db, "patch")
    if err is not None:
        return err
    await db.refresh(user)
    return _scim_response(_user_to_scim(user, request))


@router.delete("/v2/Users/{user_id}")
async def scim_delete_user(
    user_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[bool, Depends(authenticate_scim)],
):
    user = await _get_scim_user(db, user_id)
    if user is None:
        return _scim_error("User not found", status.HTTP_404_NOT_FOUND)

    # Deprovision == deactivate (soft). Guard protects LOCAL/SSO + last admin.
    allowed, reason = await can_scim_deactivate(db, user)
    if not allowed:
        return _scim_error(reason, status.HTTP_403_FORBIDDEN, scim_type="mutability")

    user.is_active = False
    await audit_log(
        db, None, "scim.user_deactivate", "user", str(user.id),
        {"userName": user.email}, ip_address=get_client_ip(request),
    )
    err = await _commit_or_500(db, "deactivate")
    if err is not None:
        return err
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


# ---------------------------------------------------------------------------
# Admin: config read + token management + enable toggle
# (manage_settings, JWT-authed — NOT SCIM bearer-authed)
# ---------------------------------------------------------------------------
@router.get("/config")
async def scim_get_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Admin view of SCIM state for the settings panel.

    ``token_configured`` reports whether an encrypted bearer token is stored
    (never the token itself — it is only revealed once at generation time).
    """
    cfg = await get_scim_config(db)
    return {
        "enabled": bool(cfg.get("enabled")),
        "token_configured": bool(cfg.get("bearer_token")),
        "base_url": "/api/scim/v2",
    }


@router.post("/token")
async def scim_generate_token(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
):
    """Generate/regenerate the SCIM bearer token. Returns the 64-hex token ONCE."""
    token = await generate_scim_token(db)
    await audit_log(
        db, current_user.id, "scim.token_generate", "scim", None, {},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"token": token, "base_url": "/api/scim/v2"}


@router.post("/enable")
async def scim_set_enabled(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_settings"))],
    enabled: bool = True,
):
    """Enable or disable SCIM provisioning."""
    await set_scim_enabled(db, enabled)
    await audit_log(
        db, current_user.id, "scim.set_enabled", "scim", None, {"enabled": enabled},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"enabled": enabled}
