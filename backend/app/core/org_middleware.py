"""Per-request organization scope middleware (tenancy boundary).

Resolves the request's ``Host`` header to an org id and pins it into the
``org_context`` contextvar for the lifetime of the request, so service-layer
queries can read it via ``get_org_id()`` and pass it to ``apply_org_scope``.

Fails open to the default org (OSS / single-tenant) for unknown/missing hosts,
and ALWAYS clears the contextvar after the request so org scope never leaks
across requests served on the same worker.

Implemented as **pure-ASGI** middleware (not ``BaseHTTPMiddleware``). Starlette's
``BaseHTTPMiddleware`` runs the downstream app in a separate ``anyio`` task, so a
``ContextVar`` set in ``dispatch`` before ``call_next`` is NOT guaranteed to be
visible to the endpoint/dependency that reads it. A pure-ASGI middleware sets the
contextvar in the same task that then awaits the downstream app, so the scope is
reliably visible at the query sites that enforce the tenant fence.

The DB session used for slug resolution is read from ``app.db.session`` at call
time (not import time), so tests that rebind ``async_session_maker`` to the test
engine exercise the full Host -> DB lookup -> org_context path against the test
database. A session is opened ONLY when a slug actually needs to be looked up;
missing / single-label / OSS hosts short-circuit to the default org without ever
touching the database (and so never touch the production engine).
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.org_constants import DEFAULT_ORG_ID
from app.models.organization import Organization
from app.services.host_to_org import extract_slug_from_host, normalize_host

logger = logging.getLogger(__name__)


class OrgScopeMiddleware:
    """Resolve Host -> org and pin it into the request-scoped contextvar.

    Pure-ASGI middleware: the contextvar is set in the same task that drives the
    downstream application, guaranteeing the scope is visible to query sites.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        host = _host_from_scope(scope)
        org_id = await self._resolve_org_id(host)

        token = _set_org_token(org_id)
        try:
            await self.app(scope, receive, send)
        finally:
            # Hard requirement: never let org scope bleed into the next request.
            _reset_org_token(token)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # Lifespan / websocket: no Host-based org scope to resolve here.
            await self.app(scope, receive, send)
            return
        await self.dispatch(scope, receive, send)

    async def _resolve_org_id(self, host: str | None):
        """Map a Host header to an org id.

        Short-circuits to the default org for missing / single-label / invalid
        hosts WITHOUT opening a DB session. Only opens a session (against the
        currently-bound ``async_session_maker``) when a real slug must be looked
        up, so non-resolvable hosts never touch the database/engine.
        """
        if not host:
            return DEFAULT_ORG_ID
        slug = extract_slug_from_host(normalize_host(host))
        if not slug:
            return DEFAULT_ORG_ID

        # Resolve the session maker at call time so tests can rebind it to the
        # test engine (see tests/conftest.py). Importing the module (not the name)
        # keeps the binding live rather than frozen at import time.
        import app.db.session as db_session

        try:
            async with db_session.async_session_maker() as session:
                org_id = (
                    await session.execute(
                        select(Organization.id).where(Organization.slug == slug)
                    )
                ).scalar_one_or_none()
            return org_id or DEFAULT_ORG_ID
        except Exception:
            # DB unreachable (boot, migration window) — preserve OSS behaviour.
            logger.warning(
                "Org resolution failed for host=%r; using default org", host
            )
            return DEFAULT_ORG_ID


def _host_from_scope(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key == b"host":
            return value.decode("latin-1")
    return None


def _set_org_token(org_id):
    from app.core import org_context

    return org_context._org_id.set(org_id)


def _reset_org_token(token) -> None:
    from app.core import org_context

    org_context._org_id.reset(token)
