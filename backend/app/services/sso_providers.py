"""Multi-provider OIDC service helpers.

Owns the per-provider Authlib client cache and the OIDC discovery probe used by
the Test-Connection endpoint. Login/callback build clients keyed by provider id
here instead of mutating one global ``oidc`` registry.
"""

import logging

import httpx
from authlib.integrations.starlette_client import OAuth

from app.core.encryption import decrypt
from app.models.sso_provider import SSOProvider
from app.services.webhooks import is_safe_url

logger = logging.getLogger(__name__)

# Per-provider OAuth registry. Keyed by provider id; rebuilt when a provider's
# config changes. NOT a single mutated "oidc" client.
_provider_oauth = OAuth()

_VALID_TOKEN_AUTH_METHODS = {"client_secret_post", "client_secret_basic", "none"}

# Required endpoints an OIDC discovery document must advertise to be usable.
_REQUIRED_DISCOVERY_KEYS = ("authorization_endpoint", "token_endpoint", "jwks_uri")


def validate_issuer_url(issuer_url: str | None) -> str:
    """Validate an OIDC issuer URL (https + SSRF-safe). Returns the cleaned URL.

    Raises ``ValueError`` with a human message if the issuer is missing, not
    https, or resolves to a private/internal address. Used both at provider
    create/update time and on the login path (build_provider_client) so a
    malicious issuer can never drive a server-side request to an internal host
    (e.g. 169.254.169.254).
    """
    issuer = (issuer_url or "").strip().rstrip("/")
    if not issuer:
        raise ValueError("Issuer URL is required")
    if not issuer.lower().startswith("https://"):
        raise ValueError("Issuer URL must use https")
    # is_safe_url resolves the host and rejects private/internal/link-local IPs.
    safe, reason = is_safe_url(f"{issuer}/.well-known/openid-configuration")
    if not safe:
        raise ValueError(reason or "Issuer URL is not allowed")
    return issuer


def _client_name(provider_id) -> str:
    return f"oidc_{provider_id}"


def build_provider_client(provider: SSOProvider):
    """Build (and cache) an Authlib client for ``provider``.

    The client is registered under a per-provider name so concurrent providers
    never collide. ``overwrite=True`` + a cache eviction makes this safe to call
    on every login/callback with the latest DB config.
    """
    name = _client_name(provider.id)

    token_auth_method = provider.token_auth_method or "client_secret_post"
    if token_auth_method not in _VALID_TOKEN_AUTH_METHODS:
        logger.warning(
            "Invalid token_auth_method %s for provider %s, defaulting to client_secret_post",
            token_auth_method,
            provider.id,
        )
        token_auth_method = "client_secret_post"

    # SSRF guard on the login path: refuse to build a client (and thus refuse to
    # make any server-side request to the discovery/token endpoints) for an
    # issuer that is non-https or resolves to a private/internal address.
    issuer_url = validate_issuer_url(provider.issuer_url)
    client_secret = (
        decrypt(provider.client_secret_encrypted)
        if provider.client_secret_encrypted
        else None
    )

    scopes = provider.scopes or "openid email profile"
    # When group sync needs an extra scope, append it if not already present.
    if provider.group_sync_enabled and provider.groups_scope:
        if provider.groups_scope not in scopes.split():
            scopes = f"{scopes} {provider.groups_scope}".strip()

    # Evict any cached client so fresh settings are used (register only refreshes
    # the registry, not the _clients cache).
    if name in _provider_oauth._clients:
        del _provider_oauth._clients[name]

    _provider_oauth.register(
        name=name,
        client_id=provider.client_id,
        client_secret=client_secret,
        server_metadata_url=f"{issuer_url}/.well-known/openid-configuration",
        client_kwargs={
            "scope": scopes,
            "token_endpoint_auth_method": token_auth_method,
        },
        overwrite=True,
    )
    return _provider_oauth.create_client(name)


def get_provider_client(provider: SSOProvider):
    """Return the cached Authlib client for ``provider``, building it if absent."""
    name = _client_name(provider.id)
    client = _provider_oauth.create_client(name)
    if client is None:
        client = build_provider_client(provider)
    return client


async def probe_oidc_discovery(issuer_url: str, timeout: float = 8.0) -> tuple[bool, str, dict]:
    """Fetch ``{issuer}/.well-known/openid-configuration`` and validate it.

    SSRF-safe: the issuer URL is validated (https scheme, public host, no
    private/internal IPs) via the shared ``is_safe_url`` guard before any
    network call.

    Returns:
        (success, message, discovery_document)
    """
    try:
        issuer = validate_issuer_url(issuer_url)
    except ValueError as exc:
        return False, str(exc), {}

    discovery_url = f"{issuer}/.well-known/openid-configuration"

    try:
        # follow_redirects=False: discovery MUST be served directly. Following a
        # redirect would re-open the SSRF hole the is_safe_url check just closed
        # (a 302 to http://169.254.169.254/... bypasses the pre-flight host check).
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.get(discovery_url)
    except httpx.HTTPError as exc:
        return False, f"Could not reach the discovery endpoint: {exc}", {}

    if resp.status_code != 200:
        return False, f"Discovery endpoint returned HTTP {resp.status_code}", {}

    try:
        doc = resp.json()
    except ValueError:
        return False, "Discovery endpoint did not return valid JSON", {}

    if not isinstance(doc, dict):
        return False, "Discovery document is malformed", {}

    missing = [k for k in _REQUIRED_DISCOVERY_KEYS if not doc.get(k)]
    if missing:
        return False, f"Discovery document missing required endpoints: {', '.join(missing)}", doc

    return True, "Discovery document is valid", doc
