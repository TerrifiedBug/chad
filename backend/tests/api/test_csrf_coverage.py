"""CSRF double-submit coverage audit.

With delegated (cookie) auth, CSRFMiddleware's double-submit check is the
primary mutation defence. This pins the exemption surface to the reviewed
allowlist: log ingest (per-index tokens, published raw on port 8001),
/api/external (API keys), /api/scim (constant-time IdP bearer), and the
three documented pre-session auth endpoints. Editing the allowlist below
is a security decision, not a refactor.
"""

from fastapi.routing import APIRoute

from app.core.csrf import CSRFMiddleware
from app.main import app

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

ALLOWED_EXEMPT_PATHS = {
    "/api/auth/sso/exchange",  # 30 s single-use exchange code
    "/api/auth/login",         # no CSRF cookie exists before first login
    "/api/auth/login/2fa",     # short-lived 2fa_token from the prior login
}
ALLOWED_EXEMPT_PREFIXES = {
    "/api/logs/",      # log ingest — per-index-pattern auth tokens (port 8001)
    "/api/external/",  # bearer-only external API keys
    "/api/scim/",      # SCIM 2.0 constant-time bearer token (IdP-driven)
}


def test_csrf_middleware_is_installed():
    assert any(m.cls is CSRFMiddleware for m in app.user_middleware)


def test_exemption_lists_match_reviewed_allowlist():
    assert CSRFMiddleware.EXEMPT_PATHS == ALLOWED_EXEMPT_PATHS
    assert set(CSRFMiddleware.EXEMPT_PREFIXES) == ALLOWED_EXEMPT_PREFIXES


def test_every_mutating_route_is_csrf_covered_or_allowlisted():
    leaks = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not (MUTATING_METHODS & set(route.methods or ())):
            continue
        path = route.path
        exempt = path in CSRFMiddleware.EXEMPT_PATHS or path.startswith(
            tuple(CSRFMiddleware.EXEMPT_PREFIXES)
        )
        allowlisted = path in ALLOWED_EXEMPT_PATHS or path.startswith(
            tuple(ALLOWED_EXEMPT_PREFIXES)
        )
        if exempt and not allowlisted:
            leaks.append(path)
    assert leaks == [], f"mutating routes exempt from CSRF outside allowlist: {leaks}"
