# Plan 011: Remove the Coverage Recommendations feature (heavy, locks up the container)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result. If a STOP condition
> occurs, stop and report. When done, update this plan's row in
> `plans/README.md` — unless a reviewer dispatched you and maintains the index.
>
> **Drift check (run first)**: `git diff --stat 821660f..HEAD -- backend/app/main.py backend/app/api/recommendations.py frontend/src/pages/AttackMatrix.tsx frontend/src/lib/api.ts`
> If these changed since this plan was written, compare against the "Current
> state" notes before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: tech-debt / feature-removal
- **Planned at**: commit `821660f`, 2026-06-15

## Why this matters

The Coverage Recommendations feature (F6 — "deploy these next" coverage-gap suggestions on the ATT&CK matrix) is being removed: it is computationally heavy, locks up the container when invoked, and is not considered useful. The expensive work is the synchronous `recommend()` computation in `services/coverage_recommendations.py` (clones/searches SigmaHQ rules and cross-references coverage), invoked on-demand by `GET /api/recommendations/coverage` when the AttackMatrix page renders. This plan removes the feature end-to-end (backend service + API + schema + tests, and the frontend component + its wiring) so nothing calls that code path. There is **no** scheduler/background job for it (verified — no scheduler wiring), so removal is a clean excision with no job to unregister.

## Current state

Backend (delete these files entirely):
- `backend/app/services/coverage_recommendations.py` — the heavy `recommend()` implementation.
- `backend/app/api/recommendations.py` — router (`APIRouter(prefix="/recommendations")`); imports `recommend` (line 20) and schemas (line 16); also imports `get_current_user, get_opensearch_client_optional` from `app.api.deps`.
- `backend/app/schemas/recommendations.py` — request/response models for the feature.
- `backend/tests/services/test_coverage_recommendations.py` — its tests.

Backend wiring to remove (edit `backend/app/main.py`):
- Line 44: `from app.api.recommendations import router as recommendations_router`
- Line 412: `app.include_router(recommendations_router, prefix="/api")`

Frontend:
- `frontend/src/components/attack/CoverageRecommendations.tsx` — delete entirely. It imports `{ recommendationsApi, CoverageRecommendation } from '@/lib/api'` and calls `recommendationsApi.coverage({ limit })`.
- `frontend/src/pages/AttackMatrix.tsx` — remove the import (line 22: `import { CoverageRecommendations } from '@/components/attack/CoverageRecommendations'`) and the render site (line ~538: `{!selectedTechnique && <CoverageRecommendations limit={8} />}`, plus the explanatory comment at ~536–537).
- `frontend/src/lib/api.ts` — remove the coverage-recommendations block (around lines 1750–1780): the `CoverageRecommendation` type, `CoverageRecommendationsResponse` type, and the `recommendationsApi` export. (Section is marked `// ── Coverage-gap rule recommendations (F6) ──`.)

Verified there are **no other importers** of these modules/symbols (grep for `api.recommendations`, `schemas.recommendations`, `services.coverage_recommendations`, `recommendationsApi`, `CoverageRecommendation` returns only the files listed above). `app/api/recommendations.py` is the only consumer of `services.coverage_recommendations` and `schemas.recommendations`.

Repo conventions: routers are registered in `main.py` via `include_router(..., prefix="/api")`; frontend API calls live in `lib/api.ts` as `*Api` objects consumed by components.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Backend imports cleanly | `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` | exit 0 |
| No dangling backend refs | `grep -rn "coverage_recommendations\|recommendations_router\|schemas.recommendations\|api.recommendations" backend/app/` | no matches |
| Backend suite (no broken imports) | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k "attack or recommend" -p no:randomly -q` | pass / no collection errors |
| Frontend build (typecheck) | `cd frontend && npm run build` | exit 0 |
| Frontend lint | `cd frontend && npm run lint` | exit 0 |
| Frontend tests | `cd frontend && npm test -- --run` | all pass |
| No dangling frontend refs | `grep -rn "CoverageRecommendation\|recommendationsApi\|coverage-recommendation" frontend/src/` | no matches |

## Scope

**In scope** — delete: `backend/app/services/coverage_recommendations.py`, `backend/app/api/recommendations.py`, `backend/app/schemas/recommendations.py`, `backend/tests/services/test_coverage_recommendations.py`, `frontend/src/components/attack/CoverageRecommendations.tsx`. Edit: `backend/app/main.py`, `frontend/src/pages/AttackMatrix.tsx`, `frontend/src/lib/api.ts`.

**Out of scope** (do NOT touch):
- The rest of the ATT&CK matrix feature (`AttackMatrix.tsx` keeps working without the recommendations panel; `attack_coverage.py`, `api/attack.py` stay).
- `app/api/deps.py` (`get_opensearch_client_optional` is used by many other routers — do not remove it).
- Any database migration — the feature has no dedicated tables (it computes on the fly). If you discover a migration/table exclusively for it, STOP and report rather than dropping schema.

## Git workflow

- Branch: stay on the current working branch (do not create/switch).
- Commit message: `feat: remove Coverage Recommendations (F6) — heavy, low-value`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Remove backend wiring, then delete backend files

1. In `backend/app/main.py`, delete the line-44 import and the line-412 `include_router` for `recommendations_router`.
2. Delete `backend/app/api/recommendations.py`, `backend/app/services/coverage_recommendations.py`, `backend/app/schemas/recommendations.py`, `backend/tests/services/test_coverage_recommendations.py`.

**Verify**: `grep -rn "coverage_recommendations\|recommendations_router\|schemas.recommendations\|api.recommendations" backend/app/` → no matches; `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` → exit 0.

### Step 2: Remove frontend usage, then delete the component

1. In `frontend/src/pages/AttackMatrix.tsx`: remove the import (line 22) and the render block (~536–538).
2. In `frontend/src/lib/api.ts`: remove the F6 block (≈1750–1780) — `CoverageRecommendation`, `CoverageRecommendationsResponse`, `recommendationsApi`.
3. Delete `frontend/src/components/attack/CoverageRecommendations.tsx`.

**Verify**: `grep -rn "CoverageRecommendation\|recommendationsApi\|coverage-recommendation" frontend/src/` → no matches.

### Step 3: Verify both sides build/test clean

**Verify**:
- `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` → exit 0
- `cd frontend && npm run build` → exit 0 (tsc catches any dangling reference)
- `cd frontend && npm run lint` → exit 0
- `cd frontend && npm test -- --run` → all pass

## Test plan

- No new tests (this is a removal). The proof is: backend imports clean with no dangling references, the frontend type-checks/builds (tsc would fail on any leftover reference to the deleted exports), and the existing frontend test suite stays green.
- If a frontend test references `CoverageRecommendations` or `recommendationsApi`, delete/adjust that test as part of Step 2 (grep will surface it).

## Done criteria

- [ ] The 5 listed files are deleted; `main.py`, `AttackMatrix.tsx`, `lib/api.ts` edited
- [ ] `grep -rn "coverage_recommendations\|recommendations_router\|api.recommendations" backend/app/` → no matches
- [ ] `grep -rn "CoverageRecommendation\|recommendationsApi" frontend/src/` → no matches
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` exits 0
- [ ] `cd frontend && npm run build` exits 0; `npm run lint` exits 0; `npm test -- --run` all pass
- [ ] `plans/README.md` status row updated (unless reviewer maintains it)

## STOP conditions

Stop and report if:
- Any "Current state" location doesn't match (drift) — especially if a NEW importer of these modules appeared.
- You find a database table/migration dedicated to coverage recommendations (don't drop schema without sign-off).
- Removing `recommendationsApi` reveals it shares a helper with another `*Api` object that is still in use.

## Maintenance notes

- The ATT&CK coverage MAP itself (`attack_coverage.py`, `api/attack.py`, the matrix UI) stays — only the "recommended next rules" panel is gone.
- If coverage recommendations are ever reintroduced, do the heavy computation off the request path (background job + cached result) rather than synchronously in the endpoint, which is what caused the container lockup.
- Reviewer: confirm `get_opensearch_client_optional` in `deps.py` was NOT removed (other routers depend on it) and that `npm run build` is clean (tsc is the real dangling-reference check).
