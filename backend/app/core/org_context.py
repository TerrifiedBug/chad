"""Per-request organization scope (tenancy boundary).

The single source of truth for "which org's data may the current execution
touch". Mirrors VectorFlow's AsyncLocalStorage org context, implemented with
``contextvars`` so the scope propagates across awaits without threading an
``org_id`` through every signature.

Entry points (request middleware / dependency, background per-org loops) call
``run_with_org(org_id, ...)`` / set the scope; service-layer queries read it via
``get_org_id()`` and pass it to ``app.services.org_scope.apply_org_scope``. When
no scope is set (boot work, un-wired path) ``get_org_id()`` returns None and the
caller falls back to the default org — OSS single-tenant behaviour.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import TypeVar

_org_id: ContextVar[uuid.UUID | None] = ContextVar("chad_org_id", default=None)

T = TypeVar("T")


def set_org_id(org_id: uuid.UUID | None) -> None:
    """Set the active org scope for the current context (request middleware)."""
    _org_id.set(org_id)


def get_org_id() -> uuid.UUID | None:
    """Read the active org scope, or None outside any org context."""
    return _org_id.get()


async def run_with_org(org_id: uuid.UUID, fn: Callable[[], Awaitable[T]]) -> T:
    """Run ``fn`` with ``org_id`` as the active scope, restoring it afterwards.

    Used by background loops that iterate organizations: one ``run_with_org`` per
    org so incidental queries inside observe the correct tenant.
    """
    token = _org_id.set(org_id)
    try:
        return await fn()
    finally:
        _org_id.reset(token)
