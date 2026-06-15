# Plan 003: Code-split heavy frontend routes (lazy-load Monaco editors & rare pages)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report. When done, update this plan's row
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- frontend/src/App.tsx`
> If `App.tsx` changed since this plan was written, compare the "Current state"
> excerpt to the live file before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: perf
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

`frontend/src/App.tsx` statically imports all ~30 page components at the top of the module (lines 10–39). Vite therefore bundles every page — including the two heaviest, `RuleEditor` and `CorrelationRuleEditor`, which pull in the Monaco code editor (`@monaco-editor/react` + `monaco-editor`, on the order of ~1MB+), plus `Reports`, `AttackMatrix`, `SigmaHQ`, `MISP`, `Health`, `FieldMappings` — into the initial JS bundle. Every user downloads and parses all of it on first load, even though most sessions never open a Monaco editor or the ATT&CK matrix. Converting the heavy/rarely-hit pages to `React.lazy` + a `Suspense` boundary moves them into separate chunks fetched on demand, shrinking the initial bundle and improving first-load time for everyone.

## Current state

- `frontend/src/App.tsx:10-39` — every page is a static default import, e.g.:

```tsx
import Dashboard from '@/pages/Dashboard'
import RulesPage from '@/pages/Rules'
import RuleEditorPage from '@/pages/RuleEditor'
...
import EnvironmentDetailPage from '@/pages/EnvironmentDetail'
```

- `frontend/src/App.tsx:72-180+` — `AppRoutes()` returns several `<Routes>` blocks (setup, OpenSearch wizard, and the main authed route table). Routes render pages inside `<AppLayout>…</AppLayout>` wrappers.
- There is a ready-made loading spinner already in the file (lines 76–90) — reuse its markup for the Suspense fallback so the UX is consistent.
- No `React.lazy` / `Suspense` exists in `App.tsx` today (`grep -n "lazy\|Suspense" frontend/src/App.tsx` → no matches).
- Test risk: several tests under `frontend/src/test/` render routed pages and assert synchronously (e.g. `integration.test.tsx`, `auth.test.tsx`, `ux-parity.test.tsx`). Lazy components resolve asynchronously, so a synchronous `getByText` on a now-lazy page will fail; those assertions need `findBy*`/`waitFor`. To bound this blast radius, **keep the auth/setup critical-path pages eager** and only lazy-load the heavy/rare ones.

Repo conventions: TypeScript + React 19, path alias `@/` → `frontend/src/`. Vite 5, ESLint flat config (`npm run lint`). Match existing import style.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Install (if needed) | `cd frontend && npm ci` | exit 0 |
| Lint | `cd frontend && npm run lint` | exit 0 |
| Tests | `cd frontend && npm test` | all pass |
| Build (proves chunking) | `cd frontend && npm run build` | exit 0; build output lists multiple JS chunks |

## Scope

**In scope**:
- `frontend/src/App.tsx`

**Out of scope** (do NOT touch):
- The page components themselves (`frontend/src/pages/*`) — no changes to their internals.
- `frontend/vite.config.ts` — route-level `lazy()` is sufficient; do not add manual `manualChunks` config in this plan.
- Provider/layout components (`ThemeProvider`, `AuthProvider`, `AppLayout`, `AppHeader`, `ProtectedRoute`, `AuthRoute`) — keep eager; they render on every route.

## Git workflow

- Branch: `advisor/003-frontend-route-code-splitting`
- Commit message: `perf(frontend): lazy-load heavy routes (Monaco editors, reports, attack map)`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add `lazy` + `Suspense` imports

At the top of `App.tsx`, add `lazy` and `Suspense` to the React import (currently the file imports from `'react-router-dom'` and hooks; add `import { lazy, Suspense } from 'react'`).

### Step 2: Convert the heavy/rare pages to `lazy`

Change ONLY these page imports from static to lazy (they are the heavy or rarely-hit routes). Each becomes:

```tsx
const RuleEditorPage = lazy(() => import('@/pages/RuleEditor'))
const CorrelationRuleEditorPage = lazy(() => import('@/pages/CorrelationRuleEditor'))
const ReportsPage = lazy(() => import('@/pages/Reports'))
const AttackMatrixPage = lazy(() => import('@/pages/AttackMatrix'))
const SigmaHQPage = lazy(() => import('@/pages/SigmaHQ'))
const MISPPage = lazy(() => import('@/pages/MISP'))
const HealthPage = lazy(() => import('@/pages/Health'))
const FieldMappingsPage = lazy(() => import('@/pages/FieldMappings'))
const OrganizationsPage = lazy(() => import('@/pages/Organizations'))
const EnvironmentsPage = lazy(() => import('@/pages/Environments'))
const EnvironmentDetailPage = lazy(() => import('@/pages/EnvironmentDetail'))
const IOCMatchesPage = lazy(() => import('@/pages/IOCMatches'))
const LiveAlertFeedPage = lazy(() => import('@/pages/LiveAlertFeed'))
```

**Keep these EAGER** (critical path / heavily used in tests): `SetupPage`, `LoginPage`, `OpenSearchWizard`, `Dashboard`, `RulesPage`, `AlertsPage`, `AlertDetailPage`, `CasesPage`, `CaseDetailPage`, `IndexPatternsPage`, `IndexPatternDetailPage`, `SettingsHub`, `SettingsSection`, `ChangePasswordPage`, `ApiKeysPage`, `AccountPage`, `ApprovalsPage`. Do not convert these.

### Step 3: Wrap the route output in a single `Suspense` boundary

In `AppRoutes()`, wrap the returned `<Routes>` element(s) that can render lazy pages in a `<Suspense>` whose `fallback` reuses the existing centered-spinner markup (lines 76–90). The cleanest single insertion point: in the top-level `App` component, wrap `<AppRoutes />` once:

```tsx
<Suspense fallback={
  <div className="flex h-screen items-center justify-center bg-background">
    <div className="animate-spin h-8 w-8 border-4 border-primary border-t-transparent rounded-full" />
  </div>
}>
  <AppRoutes />
</Suspense>
```

A single high boundary is sufficient and avoids editing every `<Route>`.

**Verify**: `cd frontend && npm run lint` → exit 0.

### Step 4: Build and confirm chunking, then run tests

`cd frontend && npm run build` — the build must succeed and the asset summary must show **multiple** JS chunks (the lazy pages become their own files). Note the largest chunk shrinks relative to before.

`cd frontend && npm test` — run the full suite.
- All green → done.
- A small number of previously-synchronous assertions on a now-lazy page fail because the page loads async → update those specific assertions to `await screen.findBy…` / `waitFor(...)` (testing-library is already a dependency; see existing `await` usage in `frontend/src/test/integration.test.tsx`).
- **More than ~6 tests break, or a test on an EAGER page breaks** → **STOP and report** — the eager/lazy split may need rebalancing; don't churn the suite blindly.

**Verify**: `cd frontend && npm test` → all pass; `npm run build` → exit 0 with multiple chunks.

## Test plan

- No new feature tests required; the deliverable is verified by `npm run build` (multiple chunks emitted) and the existing suite staying green.
- If any lazy-page test needs async-ifying, mirror the `findBy`/`waitFor` pattern already used in `frontend/src/test/integration.test.tsx`.

## Done criteria

ALL must hold:

- [ ] `grep -c "lazy(() => import" frontend/src/App.tsx` ≥ 10
- [ ] `frontend/src/App.tsx` contains a `<Suspense` boundary around the routes
- [ ] `cd frontend && npm run build` exits 0 and emits multiple JS chunks (lazy pages are separate files)
- [ ] `cd frontend && npm run lint` exits 0
- [ ] `cd frontend && npm test` all pass
- [ ] Only `frontend/src/App.tsx` (and, if unavoidable, a few test files for async assertions) modified
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- `App.tsx` doesn't match the "Current state" excerpt (drift).
- More than ~6 tests break, or any EAGER-page test breaks, after Step 4.
- The build fails to chunk (e.g. a circular import between a lazy page and an eager module) — report the import cycle.
- Making it work appears to require editing page-component internals (out of scope).

## Maintenance notes

- When adding a new page in future, default to `lazy()` for anything heavy or behind a permission/rarely-hit route; keep first-paint/auth pages eager.
- If first-load is still heavy after this, a follow-up can add Vite `manualChunks` to split vendor bundles (React, Radix, TanStack Query) — deliberately deferred here.
- Reviewer should confirm Monaco no longer appears in the main entry chunk (it should live in the `RuleEditor`/`CorrelationRuleEditor` chunks).
