"""Per-request organization scope middleware (tenancy boundary).

Resolves the request's ``Host`` header to an org id and pins it into the
``org_context`` contextvar for the lifetime of the request, so service-layer
queries can read it via ``get_org_id()`` and pass it to ``apply_org_scope``.

Fails open to the default org (OSS / single-tenant) for unknown/missing hosts,
and ALWAYS clears the contextvar after the request so org scope never leaks
across requests served on the same worker.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.org_constants import DEFAULT_ORG_ID
from app.core.org_context import set_org_id
from app.db.session import async_session_maker
from app.services.host_to_org import resolve_org_id_from_host

logger = logging.getLogger(__name__)


class OrgScopeMiddleware(BaseHTTPMiddleware):
    """Resolve Host -> org and pin it into the request-scoped contextvar."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        host = request.headers.get("host")
        try:
            async with async_session_maker() as session:
                org_id = await resolve_org_id_from_host(session, host)
        except Exception:
            # DB unreachable (boot, migration window) — preserve OSS behaviour.
            logger.warning("Org resolution failed for host=%r; using default org", host)
            org_id = DEFAULT_ORG_ID

        set_org_id(org_id)
        try:
            return await call_next(request)
        finally:
            # Hard requirement: never let org scope bleed into the next request.
            set_org_id(None)
