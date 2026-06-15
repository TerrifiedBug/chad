"""Rules API package.

Aggregates the rule sub-routers behind a single ``router`` so that
``from app.api.rules import router`` (used by ``app.main``) keeps working.

The parent ``router`` has no prefix; each sub-router carries
``prefix="/rules"``. Sub-routers are included in the same relative order the
routes were originally declared in the monolithic ``rules.py`` so effective
FastAPI route matching (static paths before ``/{rule_id}``) is preserved.

Decomposition is incremental (plan 010): routes still live in ``_pending`` until
moved into their dedicated group module.
"""

from fastapi import APIRouter

from app.api.rules import _pending, deploy, exceptions, metadata, snooze

router = APIRouter()

# Included in original route-declaration order so effective FastAPI matching
# (static paths before /{rule_id}) is preserved. _pending still holds the
# not-yet-extracted groups in their original relative order.
router.include_router(_pending.router)
router.include_router(deploy.router)
router.include_router(snooze.router)
router.include_router(exceptions.router)
router.include_router(metadata.router)
