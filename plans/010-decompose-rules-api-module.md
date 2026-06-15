# Plan 010: Decompose the `api/rules.py` god module into a `rules/` package (URL-preserving)

> **Executor instructions**: This is a LARGE, HIGH-RISK refactor. Do the
> characterization-test safety net FIRST (Step 1) and do NOT proceed to the
> split until the OpenAPI path snapshot is captured and green. Work one route
> group at a time; keep the suite green between groups. If a "STOP condition"
> occurs, stop and report. When done, update this plan's row in
> `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/api/rules.py backend/app/main.py`
> If either changed since this plan was written, the route map below may be
> stale — re-derive it before proceeding; on a mismatch, treat as a STOP.

## Status

- **Priority**: P3
- **Effort**: L (multi-day)
- **Risk**: HIGH (every rule endpoint routes through this file; route shadowing or a dropped route is a production outage)
- **Depends on**: 001 (a trustworthy green backend CI is a prerequisite for a refactor this size)
- **Category**: tech-debt / architecture
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

`backend/app/api/rules.py` is 3152 lines (≈22× the backend median file) with 36 routes spanning CRUD, validation, testing, deploy/undeploy/rollback, snooze, exceptions, comments, activity, and versions. Everything about rules funnels through one file: high cognitive load, merge-conflict magnet, and hard to reason about the rule lifecycle. Splitting it into a `rules/` package of focused sub-routers (one per concern) — **while preserving every URL and response shape exactly** — makes each concern independently readable and testable without changing the API surface. The win is maintainability; the risk is that a careless split drops or shadows a route. This plan mitigates that risk with an OpenAPI path-snapshot gate and an incremental, one-group-at-a-time approach.

## Current state

- Mounted in `backend/app/main.py:48,375`:

```python
from app.api.rules import router as rules_router
...
app.include_router(rules_router, prefix="/api")
```

- `backend/app/api/rules.py:107` — `router = APIRouter(prefix="/rules", tags=["rules"])`. So all paths are `/api/rules…`.
- Lines 1–272 (before the first route) hold imports, Pydantic schemas, and shared helper functions used across routes. These are the shared surface that must remain importable after the split.
- **The 36 routes and their natural groups** (line → method path):

| Group | Routes |
|---|---|
| **crud** | `273 GET ""`, `366 GET /index-fields/{index_pattern_id}`, `411 POST /check-title`, `449 GET /settings`, `462 PUT /settings`, `480 POST ""`, `553 GET /{rule_id}`, `639 PATCH /{rule_id}`, `767 DELETE /{rule_id}` |
| **testing** | `805 POST /validate`, `940 POST /check-deployment-eligibility`, `969 GET /{rule_id}/deploy-preview`, `1069 POST /test`, `1236 POST /{rule_id}/test-historical` |
| **deploy** | `1316 POST /bulk/deploy`, `1472 POST /{rule_id}/deploy`, `1574 POST /bulk/undeploy`, `1798 POST /{rule_id}/undeploy`, `1901 POST /{rule_id}/rollback/{version_number}`, `1977 POST (…redeploy…)` |
| **snooze** | `2103 POST /bulk/snooze`, `2180 POST /bulk/unsnooze`, `2240 POST /{rule_id}/snooze`, `2369 POST /{rule_id}/unsnooze`, `2526 PATCH /{rule_id}/threshold` |
| **exceptions** | `2582 GET /{rule_id}/exceptions`, `2602 POST (…exceptions…)`, `2698 PATCH (…)`, `2733 DELETE (…)` |
| **metadata** | `2771 GET /{rule_id}/fields`, `2859 GET /{rule_id}/linked-correlations`, `2900 POST /bulk/delete`, `2962 GET /{rule_id}/comments`, `2992 POST /{rule_id}/comments`, `3034 GET /{rule_id}/activity`, `3117 GET /{rule_id}/versions/{version_number}` |

- **Critical FastAPI ordering constraint**: static paths (`/settings`, `/validate`, `/test`, `/check-title`, `/check-deployment-eligibility`, `/index-fields/{...}`, `/bulk/*`) must be matched **before** the parameterized `/{rule_id}` route, or `/{rule_id}` will swallow them. Within a single router FastAPI matches in declaration order; across included routers it matches in include order. The split must preserve effective ordering.

Repo conventions: routers live under `app/api/`, each module exposes `router = APIRouter(prefix=..., tags=[...])`. See any smaller router (e.g. `app/api/jira.py`) for the minimal shape.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full backend suite | `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` | all pass |
| Rule API tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k rule -q` | all pass |
| OpenAPI snapshot test | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api/test_rules_openapi_snapshot.py -q` | passes before AND after split |
| Lint | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/api/` | exit 0 |

## Scope

**In scope**:
- `backend/app/api/rules.py` → converted into a package `backend/app/api/rules/` (`__init__.py` + sub-modules).
- `backend/app/main.py` — only if the import path needs adjusting (it should NOT: keep `from app.api.rules import router` working by exporting `router` from `rules/__init__.py`).
- `backend/tests/api/test_rules_openapi_snapshot.py` (create — the safety net).

**Out of scope** (do NOT touch):
- Any route's *behavior*, request/response schema, status code, or dependency wiring. This is a pure move; logic stays byte-identical.
- `correlation_rules.py` (a separate router) — not part of this plan.
- Other god modules (`scheduler.py`, `export.py`, `auth.py`) — separate plans.

## Git workflow

- Branch: `advisor/010-decompose-rules-api-module`
- Commit per route group moved (so each commit is independently green): `refactor(rules): extract <group> routes into rules/<group>.py`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Build the safety net FIRST (do not skip)

Create `backend/tests/api/test_rules_openapi_snapshot.py` that asserts the exact set of rule routes and methods is stable. It should build the app, read `app.openapi()["paths"]`, filter keys starting with `/api/rules`, collect `(path, sorted(methods))`, and assert the set equals a hardcoded expected snapshot (the 36 routes above, with their methods and path params). Pattern: it only needs the FastAPI `app` object — no DB. Example assertion target: the snapshot is a sorted list of `"METHOD /api/rules/{rule_id}/deploy-preview"`-style strings.

Run it against the **current** `rules.py` and confirm it passes. This snapshot is your invariant: it must stay green through every subsequent commit.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api/test_rules_openapi_snapshot.py -q` → passes.

### Step 2: Create the package skeleton, keep the import stable

- Convert `backend/app/api/rules.py` into `backend/app/api/rules/__init__.py` (move the file).
- In `__init__.py`, define a parent `router = APIRouter()` (no prefix) and plan to `include_router` each sub-router. Keep `from app.api.rules import router` working in `main.py` — export `router` from the package `__init__`.
- Move the shared imports/schemas/helpers (current lines 1–272) into `rules/_shared.py` (or keep them in `__init__.py` if cleaner) so sub-modules can import them.

At this point everything still lives in `__init__`/`_shared`; the suite and snapshot must still be green. Commit.

**Verify**: snapshot test + `pytest tests/api -k rule -q` → all pass.

### Step 3: Extract one group at a time

For each group in the table (suggested order: **metadata → exceptions → snooze → deploy → testing → crud**, i.e. leaf-most/least-shared first, CRUD last):
1. Create `rules/<group>.py` with `router = APIRouter(prefix="/rules", tags=["rules"])`.
2. Move that group's route functions into it; import shared helpers/schemas from `_shared`.
3. In `rules/__init__.py`, `include_router(<group>.router)`.
4. **Preserve effective route ordering**: include the routers so that all static-path routes are registered before the `/{rule_id}` parameterized routes. Simplest safe approach — put every static-path route (`""`-list, `/settings`, `/validate`, `/test`, `/check-title`, `/check-deployment-eligibility`, `/index-fields/*`, `/bulk/*`) into earlier-included routers, and the `/{rule_id}` and `/{rule_id}/…` routes into later-included ones. If unsure, keep static and parameterized routes in their original relative order within one router rather than splitting a static and a `/{rule_id}` route across an ordering boundary.
5. Run the snapshot test + rule API tests after EACH group. If the snapshot changes, you dropped/renamed/shadowed a route — fix before continuing. Commit per group.

**Verify (after each group)**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api/test_rules_openapi_snapshot.py tests/api -k rule -q` → all pass.

### Step 4: Final sweep

- Confirm no route logic changed (the diff should be moves only — use `git diff` to sanity-check that function bodies are identical to the originals).
- `rules.py` (single file) no longer exists; `rules/` package does.

**Verify**: full suite `pytest -q` green; `ruff check app/api/` exit 0; snapshot green.

## Test plan

- **Primary safety net**: `test_rules_openapi_snapshot.py` — the full set of `/api/rules*` paths+methods is identical before and after. This is the machine-checkable proof that no route was dropped or shadowed.
- The existing rule API tests (`tests/api -k rule`) must stay green throughout (behavior unchanged).
- No new behavioral tests are required (pure refactor), but if any route group had thin coverage you discover during the move, note it for a follow-up — do not expand scope here.

## Done criteria

ALL must hold:

- [ ] `test_rules_openapi_snapshot.py` exists and passes (the 36-route snapshot is unchanged)
- [ ] `backend/app/api/rules/` is a package; `from app.api.rules import router` still works; `main.py` unchanged (or import-only)
- [ ] No single sub-module exceeds ~600 lines (the split actually reduced size)
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` → all pass
- [ ] `ruff check app/api/` exits 0
- [ ] `git diff` shows route function bodies are moves, not rewrites
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- The route map above doesn't match the live file (drift) — re-derive before any move.
- The OpenAPI snapshot changes after a move and you can't immediately see why (a route was shadowed by `/{rule_id}` ordering, or a path/method changed).
- A "move" can't stay behavior-identical because a route depends on module-level state that's awkward to share — report it; do not redesign the route.
- Coverage is so thin that you can't trust the suite to catch a behavior regression — report it; the human may want characterization tests added first (a prerequisite plan).

## Maintenance notes

- After this lands, the same pattern (package of prefixed sub-routers aggregated in `__init__`) is the template for decomposing the other god modules (`scheduler.py`, `export.py`, `auth.py`, `correlation_rules.py`) — each its own plan.
- Reviewer should diff with `--color-moved` to confirm bodies are unchanged, and re-run the OpenAPI snapshot mentally against the route table.
- Keep the snapshot test permanently — it now guards every future rules-router change against accidental route loss.
