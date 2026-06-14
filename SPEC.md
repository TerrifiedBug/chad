# Spec: CHAD ⇄ VectorFlow UX Parity + Git Sync + MISP Auto-Push

> Status: **Approved for autonomous implementation** (2026-06-14)
> Source of truth for the end-to-end build. Two recon workflows audited both
> CHAD (`/Users/danny/VSCode/workspace/chad`) and the VectorFlow reference
> (`/Users/danny/VSCode/workspace/github/vectorflow`). Decisions in §3 are final.

---

## 1. Objective

Make CHAD look and behave as if it and VectorFlow are one integrated product by
the same company, and close three functional gaps surfaced while comparing them.

**Who:** SOC operators and platform admins using CHAD's web console.

**Five workstreams:**

- **A — Shell parity.** Sidebar (`AppRail`) + top bar (`AppHeader`) match VF's
  density, badges, avatar, tokens.
- **B — Settings-as-sidebar.** Clicking Settings turns the rail into a settings
  nav panel (VF pattern); each settings section is its own route.
- **C — Git change-history sync.** Rule/config changes sync to a git repo
  (config-as-code), one-way push on deploy. Net-new.
- **D — Push IOCs into MISP.** Auto-record *sightings* against known MISP IOCs
  when CHAD alerts on them (not just pull from MISP). The push client exists; add
  the auto-trigger.
- **E — Threat-intel Redis cache.** Already shipped; add tunability + correct
  invalidation.

**Success = 1:1 VF shell look in dark mode, deep-linkable settings, rules
pushed to git on deploy, opt-in MISP sightings, all CI checks green, zero
regression to existing themes / TI-MISP behavior, no production deploy.**

---

## 2. Tech Stack

- **Frontend:** React 18 + TypeScript, Vite, react-router-dom v6, TanStack Query,
  Tailwind (`darkMode: 'class'`) + shadcn/ui (HSL semantic vars) + a "VF console"
  raw-hex token layer in `frontend/src/styles/globals.css`, lucide-react icons,
  Vitest + React Testing Library. Package manager: **pnpm** (never npm/yarn).
- **Backend:** Python / FastAPI, SQLAlchemy 2.0, Alembic, Pydantic v2, APScheduler
  (Redis leader-elected) + a Redis-stream worker, httpx, Redis (`redis>=5.0.0`),
  Postgres, OpenSearch (percolator for Sigma). Pytest, ruff, mypy.
- **New backend dependency (approved):** `GitPython` for feature C.
- **Reference only:** VectorFlow is Next.js + Prisma + shadcn; we mirror its
  *UX patterns and token values*, not its stack.

---

## 3. Scope Decisions (FINAL — do not re-litigate during the build)

1. **C / Git sync = ONE-WAY PUSH ONLY.** CHAD → git on successful deploy. The
   `gitops_mode` enum reserves `off | push | bidirectional | promotion`, but only
   `off` and `push` are wired and selectable. **Never** build inbound webhooks,
   bidirectional import, or promotion/PR flow in this effort — inbound modes can
   mutate live detection rules and are explicitly out of scope.
2. **D / MISP push = SIGHTINGS ONLY.** Auto-record a sighting against an
   already-known MISP attribute (`IOCMatch.misp_attribute_uuid`) when CHAD alerts
   on it. **Never** auto-create MISP events/attributes. Gated behind a new
   `misp_auto_push` Setting, **default OFF**. Sightings-only inherently avoids a
   pull→push→pull loop (we only sight what we pulled).
3. **B / Settings = FULL VF PARITY (route split).** Decompose the monolithic
   `Settings.tsx` (~106KB, `?tab=` switch) into per-section routes
   (`/settings/general`, `/settings/ti`, …) and add the VF sliding settings nav
   panel + back-arrow. Delete the orphaned `SettingsSidebar.tsx` after lifting its
   `settingsGroups` into a shared config.
4. **A / Shell extras:** INCLUDE — snap dark-theme tokens to VF exactly; add a
   **team switcher** pill; add the **global squared-corners** type floor. EXCLUDE
   — docs/Help icon. Plus default cosmetics (always included): square red alert
   badges, 24px squared avatar, unify badge cap to `99+`, settings back-arrow.
5. **E / TI cache:** refine only (tunable TTL, provider-fingerprint cache key,
   flush on reinit). The cache itself already works.

---

## 4. Commands

Frontend (run in `frontend/`):

```
pnpm install            # deps
pnpm dev                # vite dev server (:5173)
pnpm build              # tsc -b && vite build
tsc -b                  # typecheck (no standalone "typecheck" script)
pnpm lint               # eslint .
pnpm test               # vitest (watch)
pnpm exec vitest run    # one-shot (CI uses: npm test -- --passWithNoTests)
```

Backend (run in `backend/`):

```
pytest                                      # tests (CI: pytest --cov=app --cov-report=xml)
ruff check .                                # lint
mypy                                        # typecheck (strict; not in CI gate)
alembic upgrade head                        # apply migrations
alembic revision --autogenerate -m "msg"    # new migration
```

Full dev stack (Postgres + Redis + OpenSearch + worker):

```
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml run --rm backend pytest
```

**CI required checks (repo ruleset, all must pass to merge):**
`test-backend`, `test-frontend`, `validate-k6-scripts`, `docker-build-status`, `changes`.

---

## 5. Project Structure (key files for this work)

```
frontend/src/
  components/
    AppLayout.tsx        # shell composition; renders AppHeader + AppRail (every authed page)
    AppRail.tsx          # left rail; navSections + settingsItem; ADD settings slide-in panel
    AppHeader.tsx        # top bar; ADD team switcher, square avatar
    SettingsSidebar.tsx  # ORPHANED — lift settingsGroups out, then DELETE
    NotificationBell.tsx # badge cap 9+ → 99+, square red
    EnvironmentSelector.tsx
    CommandPalette.tsx   # imports navSections/settingsItem — keep in sync
  config/
    settingsNav.ts       # NEW — single source of truth for settings nav (panel + hub + palette)
  pages/
    SettingsHub.tsx      # /settings overview tile grid → link to per-section routes
    Settings.tsx         # ~106KB monolith — SPLIT into pages/settings/*
    settings/            # SsoSettings.tsx lives here; add the 12 other section pages
    EnvironmentDetail.tsx# ADD "Git Integration" card
  styles/globals.css     # token snap (.dark only) + squared-corners type floor
  lib/api.ts             # add environmentsApi.git.*, mispApi auto-push toggle
  App.tsx                # routes: split /settings/hub?tab → /settings/<id>; keep legacy redirects

backend/app/
  models/
    environment.py       # ADD git_* columns
    rule.py              # ADD git_path; RuleVersion already = native change history
  services/
    git/                 # NEW — GitSyncService (GitPython)
    ti/
      manager.py         # E: tunable TTL + fingerprint key + flush on reinit
      misp_feedback.py   # D: reuse record_sighting (do NOT add a 6th client copy)
    deployment.py / rule_redeploy.py   # C: enqueue git-sync job after deploy
    alerts.py            # D: hook auto-sighting at create_alert chokepoint
    scheduler.py         # C: add git_sync_job retry task (Redis-leader-locked)
  api/
    environments.py      # C: git config endpoints
    misp_feedback.py     # D: reuse create_feedback_service
  models/git_sync_job.py # NEW
  alembic/versions/      # NEW migrations (env git cols, rule.git_path, git_sync_job, settings)
```

Docs: update user-facing docs for new features. Verify path — workspace
convention is `docs/public/` + `docs/public/SUMMARY.md`; the CHAD repo may use
`/docs`. Only commit public docs.

---

## 6. Code Style & Conventions

**Backend — adding a feature** (canonical: `api/teams.py` + `schemas/team.py`):

```python
# models/X.py — SQLAlchemy 2.0
class GitSyncJob(Base):
    __tablename__ = "git_sync_job"
    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey("environments.id"))
    # ...

# schemas/X.py — Pydantic v2
class EnvGitConfigUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    git_repo_url: str | None = None
    git_token: str | None = None        # write-only; never echoed back

# api/X.py
router = APIRouter(prefix="/environments", tags=["environments"])

@router.put("/{env_id}/git")
async def set_git_config(
    env_id: int,
    body: EnvGitConfigUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(require_permission_dep("manage_environments")),
):
    # ... persist (encrypt token) ...
    await audit_log(db, user.id, "environment.git.update", "environment",
                    str(env_id), {"mode": body.gitops_mode}, ip_address=get_client_ip(request))
```

Register routers in `app/main.py` (`app.include_router(X_router, prefix="/api")`).
Background work → APScheduler job in `services/scheduler.py` (Redis-locked,
leader-elected, like `misp_ioc_sync`). Always add an Alembic migration for new
tables/columns. Secrets encrypted via `app.core.encryption`. Redact
`https?://[^@]+@` from any logged git URL.

**Frontend — adding a page:**

```tsx
// pages/settings/TiSettings.tsx — TanStack Query
const { data } = useQuery({ queryKey: ['ti-config'], queryFn: tiApi.get })

// lib/api.ts — api client auto-attaches JWT + CSRF + X-CHAD-Environment
export const environmentsApi = {
  git: {
    get: (id: number) => api.get<EnvGitConfig>(`/environments/${id}/git`),
    update: (id: number, d: EnvGitConfigUpdate) => api.put(`/environments/${id}/git`, d),
    test: (id: number) => api.post(`/environments/${id}/git/test`, {}),
    disconnect: (id: number) => api.delete(`/environments/${id}/git`),
  },
}

// App.tsx
<Route path="/settings/ti" element={
  <ProtectedRoute permission="manage_settings"><AppLayout><TiSettings /></AppLayout></ProtectedRoute>
} />
```

**Styling:** Tailwind + shadcn HSL vars + VF console raw-hex tokens
(`bg-bg-*`, `border-line`, `text-fg-*`, `bg-accent-brand-soft`, `text-status-*`).
Use `.vf-mono-xs` (11px) / `.vf-mono-sm` (12px) utilities for shell chrome —
matches the existing `AppRail`/`AppHeader` idiom. Active nav item:
`border-l-2 border-l-accent-brand bg-accent-brand-soft text-foreground font-semibold`.

---

## 7. Feature Specs

### A — Shell parity (`AppRail`, `AppHeader`, `globals.css`)

**Default cosmetics (always):**
- Alert/approvals badge: `rounded-full bg-primary` green pill → **square red**:
  `rounded-[3px] bg-status-error text-status-error-foreground`, mono 11px
  (`.vf-mono-xs`), keep `99+` cap. (`AppRail.tsx:196-207`)
- `NotificationBell` badge: cap `9+` → `99+`; square red `rounded-[3px]`.
  (`NotificationBell.tsx:61-68`)
- Avatar: circle `h-7 w-7 rounded-full` → **24px squared** `h-6 w-6 rounded-[3px]`,
  mono initials, keep the dropdown menu. (`AppHeader.tsx:149-155`)

**Token snap to VF (`.dark` block ONLY — leave light + Classic palettes intact):**
Set in `globals.css .dark`:
`--fg:#e6e8ec`, `--fg-1:#a8adb6`, `--fg-2:#6b727d`, `--fg-3:#454b54`,
`--bg-1:#0e1013`, `--bg-3:#1a1e25`, `--bg-4:#252a32`, `--line:#1f2329`,
`--accent-brand-2:#5fb83a`, `--status-error:#f87171`, `--status-degraded:#fbbf24`,
`--status-healthy:#4ade80`, `--status-info:#60a5fa`. (Keep `--accent-brand:#7dd957`,
`--bg:#0a0b0d`, `--bg-2:#14171c`, `--radius:3px` — already exact.) Document that
the prior intentional lighter-contrast tuning is being dropped for 1:1 parity.

**Global squared corners (VF type floor):** add a `globals.css` override mapping
`rounded-full` → `var(--radius)` app-wide, with an escape-hatch utility
`.rounded-dot { border-radius: 9999px }` applied to the genuine dots that must
stay circular (footer pulse dot, Health status dot, any small status indicators).
Verify no circular control becomes a visually-broken squircle.

**Team switcher (net-new):** add a `TeamSwitcher` pill to `AppHeader`, left of
`EnvironmentSelector`, mirroring its pattern: Users icon + active team name +
`ChevronDown`, `h-7`. Back it with the existing teams backend (`api/teams.py`).
Implement a `TeamProvider` context (active team persisted to localStorage). The
api client may attach an `X-CHAD-Team` header **only if** the backend already
consumes it; otherwise keep the selector cosmetic/context-only and DO NOT break
existing environment scoping. Verify backend team-scoping support before wiring
the header.

**Minor polish (optional, low priority):** header `bg-bg-1`→`bg-bg`; search
`min-w-[280px]`→`320px`; env pill `h-7 min-w-[150px]`. Skip if time-constrained.

**Keep:** the 3-state theme toggle (CHAD supports light mode; intentional
divergence from VF's dark-only). CHAD's NavBell rich dropdown (a feature upgrade).

**Acceptance:** dark-mode shell visually matches VF screenshots for badges,
avatar, contrast, and corner radius; team switcher lists & persists a team; light
+ Classic themes unchanged; existing frontend tests green.

### B — Settings as sliding sidebar + per-route pages

**Routing:** create real routes for every settings section currently behind
`?tab=`: `general, notifications, security, sso, ai, geoip, ti, webhooks, queue,
opensearch, health, backup, users` → `/settings/<id>`, each wrapped in
`AppLayout` + `ProtectedRoute permission="manage_settings"` (finer perms for
`users`, `audit`, `system-logs`, `api-keys`). Keep `audit`, `system-logs`,
`api-keys`, `account` as their existing dedicated pages.

**Decompose `Settings.tsx`:** extract each inline `?tab` block into its own
component under `pages/settings/` (reuse existing `Notifications`,
`GeoIPSettings`, `TISettings`, `EnrichmentWebhooksSettings`, `SsoSettings`). One
section → one page. Preserve all current functionality and sub-components.

**Shared nav config:** create `frontend/src/config/settingsNav.ts` exporting the
grouped settings nav (lift `settingsGroups`/`adminLinks` out of the orphaned
`SettingsSidebar.tsx`, update hrefs to `/settings/<id>`). Single source of truth
for the slide-in panel, `SettingsHub` tile grid, and `CommandPalette`.

**Slide-in panel (`AppRail`):** read `const { pathname } = useLocation()`,
`const isSettingsMode = pathname.startsWith('/settings')`. Wrap nav content in a
`relative overflow-hidden` container holding two `absolute inset-0` sibling
panels — main nav and settings nav — toggled with
`cn('transition-transform duration-200 ease-out', isSettingsMode ? '-translate-x-full opacity-0 pointer-events-none' : 'translate-x-0')`
(main) and the inverse (settings). Settings panel renders from `settingsNav.ts`
with the same active-state styling. Handle the mobile `Sheet` branch too.

**Back affordance:** in settings mode, swap the rail's "C" logo header for
`<ArrowLeft/> Settings` → `navigate('/')`.

**`SettingsHub`:** stays at `/settings` as the overview tile grid; tiles link to
`/settings/<id>` routes (not `?tab=`). Drive tiles from `settingsNav.ts`.

**Cleanup:** delete `SettingsSidebar.tsx` (dead). Update `App.tsx`: replace the
`?tab=` redirects, keep legacy `/settings/hub?tab=X` → `/settings/X` and old
`/settings/users` etc. redirects working. Update `CommandPalette` to surface
settings sub-sections from `settingsNav.ts`.

**Acceptance:** each settings section is its own deep-linkable URL; rail slides
to settings nav on `/settings/*` and back; back-arrow returns to app; no `?tab`
monolith switching remains; all prior settings functionality intact; legacy
redirects still resolve; tests green. **High blast radius — every authed page
renders through `AppLayout`/`AppRail`; verify nav never blanks on desktop or
mobile.**

### C — Git change-history sync (one-way push)

**Data model (migrations, all backward-compatible — nullable/defaulted):**
- `environments`: `git_repo_url` (str, null), `git_branch` (str, default `'main'`),
  `git_token_encrypted` (str, null), `gitops_mode`
  (enum `off|push|bidirectional|promotion`, default `off`), `git_provider`
  (str, null), `git_webhook_secret_encrypted` (str, null — reserved, unused now).
- `rules`: `git_path` (str, null).
- New `git_sync_job`: `environment_id` FK, `rule_id` FK (null), `action`
  (`commit|delete`), `file_path`, `yaml_content` (text), `commit_message`,
  `author_name`, `author_email`, `attempts` (default 0), `max_attempts`
  (default 3), `last_error` (text null), `status` (`pending|running|done|failed`),
  `next_retry_at`, `created_at`.

**Service (`services/git/git_sync.py`, GitPython):** `GitSyncService` — shallow
clone to a tmpdir (or per-env working copy), write file at
`<env-slug>/<rule-slug>.yml` from `Rule.yaml_content`, commit as the acting user
(author name/email from the audit actor), push over
`https://<token>@host/...`. Slug: lowercase, `[^a-z0-9]+`→`-`, trim, fallback
`unnamed`. Persist `Rule.git_path` on first sync (stable across renames — keep the
original path, or `git mv` on rename). Token injected only into the URL; redacted
from all logs.

**Trigger (one-way, non-blocking, push mode only):** after a successful deploy
and `RuleVersion` write in the deployment apply path
(`services/deployment.py` / `rule_redeploy.py`), if
`env.gitops_mode == 'push'` and `git_repo_url` + token present, insert a
`git_sync_job` (`commit`). Rule delete → insert a `delete` job (git rm). Do **not**
commit on every edit — `RuleVersion` rows are the local history; git reflects
deploys. Never block or fail a deploy because git failed.

**Retry worker:** add a `git_sync_job` processor to `services/scheduler.py`
(every 30s, Redis-leader-locked): process `pending` jobs; on failure back off
`[30s, 2m, 10m]`, `max_attempts=3`, then `status=failed` + audit entry +
notification.

**API (`api/environments.py`, `manage_environments`, audited):**
`PUT /environments/{id}/git` (set repo/branch/token/mode/provider — token
write-only, masked in responses), `POST /environments/{id}/git/test`
(ls-remote/clone probe), `DELETE /environments/{id}/git` (disconnect, clear
fields). Only `off` and `push` selectable for `gitops_mode`.

**Frontend:** "Git Integration" card on `EnvironmentDetail.tsx` — repo URL,
branch, masked token, mode select (Off / Push; others disabled "coming soon"),
provider select, Save / Test (show result) / Disconnect. (No inbound webhook URL —
push mode doesn't need it.) `environmentsApi.git.*` in `lib/api.ts`.

**Acceptance:** configure git on an env; deploy a rule → YAML committed at
`<env>/<rule>.yml` as the acting user; delete handled; failures retried + surfaced
in audit; token never logged or returned; deploy never blocked by git; only
`push` functional; migration applies cleanly forward.

### D — MISP auto-push (sightings only)

- New Setting key `misp_auto_push` (bool, **default False**), mirroring the
  existing `misp_sync` Setting pattern.
- Hook at the alert chokepoint (`AlertService.create_alert`, `alerts.py:369`, or
  precisely where an `IOCMatch` carrying `misp_attribute_uuid` is created): when
  the IOC is MISP-sourced (`misp_attribute_uuid` present) and `misp_auto_push` is
  ON, record a sighting via `MISPFeedbackService.record_sighting(uuid, source="CHAD")`.
  Reuse `create_feedback_service` (`api/misp_feedback.py`) — do not add a 6th
  client construction.
- **Sightings only** — never create events/attributes. This avoids
  pull→push→pull loops.
- Non-blocking (background task / worker) — never block alert creation.
- Dedup: short-TTL Redis guard `chad:misp:sighting:{uuid}` to avoid duplicate
  sightings during alert storms.
- Identity: runs with no user → audit as a **system actor**; gated by the flag,
  not the `manage_alerts` permission (which guards the manual dialog).
- Frontend: toggle "Auto-record sightings to MISP" in the TI/MISP settings page.

**Acceptance:** flag ON → an alert from a MISP-sourced IOC records exactly one
sighting (deduped) against its `misp_attribute_uuid` (verified with a mocked
feedback client); flag OFF (default) → no auto-push; no events created; alert
creation latency unaffected; system-actor audit entry written.

### E — TI cache refinements (`services/ti/manager.py`)

- Make the enrichment-cache TTL runtime-tunable via a Setting (precedent:
  `enrichment_webhook` `cache_ttl_seconds`), passed into `TIEnrichmentManager`
  instead of constructor-only `DEFAULT_CACHE_TTL_SECONDS`.
- Add an enabled-provider fingerprint / cache-version segment to the cache key
  (`chad:ti:cache:{ver}:{type}:{indicator}`) so provider config changes don't
  serve stale verdicts.
- On `reinitialize_ti_manager` (`enrichment.py:171`), flush `chad:ti:cache:*`
  (non-blocking `SCAN` + delete).

**Acceptance:** changing TI provider config invalidates the cache (test); TTL
configurable; flush-on-reinit covered by a test. Confirm during impl whether this
targets the enrichment cache (`manager.py`) vs the IOC-pull cache
(`ioc_cache.py`) — target the enrichment cache.

---

## 8. Testing Strategy

- **Backend (`pytest`):** new unit/integration tests per feature. Git sync:
  push/commit/delete against a temporary local **bare** repo (no network) + slug
  + token-redaction + retry/backoff; trigger fires only in `push` mode and never
  blocks deploy. MISP: auto-sighting with a mocked `MISPFeedbackService` — ON
  records one (deduped) sighting, OFF records none, no event creation, system
  audit entry. TI cache: invalidation on config change + flush on reinit
  (mocked/fake Redis). All new migrations apply via `alembic upgrade head`.
  `ruff check .` clean; `mypy` clean on touched modules.
- **Frontend (`vitest` + RTL):** AppRail settings-mode slide (main↔settings panel
  on route change), each new settings route renders, square red badge, squared
  avatar, `TeamSwitcher` lists/persists, `EnvironmentDetail` git card
  save/test/disconnect, legacy settings redirects resolve. **The existing 139
  frontend tests must stay green.** `pnpm lint` + `tsc -b` clean.
- **CI gate:** all 5 required checks pass (`test-backend`, `test-frontend`,
  `validate-k6-scripts`, `docker-build-status`, `changes`).
- No new e2e required; don't regress existing Playwright specs.

---

## 9. Boundaries

**Always:**
- Run `pytest` + `ruff` (backend) and `vitest run` + `pnpm lint` + `tsc -b`
  (frontend) before every commit; fix failures, never delete/skip tests to go
  green.
- Keep migrations backward-compatible + idempotent (new columns nullable/defaulted).
- Encrypt secrets (git token, webhook secret) via `app.core.encryption`; redact
  tokens from logs and API responses.
- Make git push and MISP push **non-blocking** side-effects — never block a deploy
  or alert creation on them.
- Touch only the `.dark` block for token snap; keep light + Classic palettes and
  the theme toggle intact.
- Keep `CommandPalette` in sync with nav config; keep legacy settings redirects working.
- Feature branch → squash PR. Clean commit/PR messages, **no AI attribution / no
  co-author lines**.

**Ask first (autonomous mode → pick the safe default below + record it, do NOT
prompt):**
- New runtime deps beyond `GitPython` → avoid; reuse what's present.
- Changing CI config or the 5 required checks → don't.
- Destructive/irreversible data migration → don't; additive only.

**Never:**
- Build git **bidirectional/promotion/inbound** in this effort (push only).
- Auto-create MISP **events/attributes** (sightings only).
- Regress CHAD's TI/MISP subsystem (it already exceeds VF).
- Commit secrets; push directly to `main`; **deploy to production** (prod is a
  manual Komodo step, out of scope).
- Add AI attribution to commits/PRs.

---

## 10. Implementation Plan (phased)

- **Phase 0 — Setup:** create feature branch `feat/vf-parity-gitsync-misp`. Add
  `GitPython` to backend deps.
- **Phase 1 — Backend (parallelizable, independent):**
  C git-sync (models + migration + `GitSyncService` + scheduler retry + API),
  D MISP auto-sighting (Setting + hook + dedup), E TI cache refinements.
- **Phase 2 — Frontend shell:** A (token snap + squared corners + badges + avatar
  + team switcher) → then B (shared `settingsNav.ts`, route split, slide-in
  panel, hub/palette/redirect updates, delete dead sidebar). B depends on the
  shared config from A's cleanup ordering.
- **Phase 3 — Frontend feature UI:** `EnvironmentDetail` git card (C), TI/MISP
  settings toggles (D + E).
- **Phase 4 — Verify:** full backend + frontend test/lint/typecheck; manual
  smoke via dev compose; update docs.
- **Phase 5 — Ship:** open ONE squash PR (or a small set split by workstream if
  cleaner) targeting `main`; ensure all 5 CI checks pass. Do not merge or deploy.

Highest-risk items: B (touches the shell every page renders through) and C
(net-new secret handling + side-effects on deploy). Verify both with extra care.

---

## 11. Success Criteria

- [ ] Dark-mode shell matches VF for badges (square red), avatar (24px square),
      contrast (snapped tokens), corner radius (global type floor); team switcher
      present and functional; light/Classic themes + theme toggle unchanged.
- [ ] Every settings section is a deep-linkable `/settings/<id>` route; rail
      slides to a settings nav panel with a back-arrow; no `?tab` monolith; legacy
      redirects still resolve; `Settings.tsx` decomposed; `SettingsSidebar.tsx`
      deleted.
- [ ] Configuring git on an environment and deploying a rule pushes
      `<env>/<rule>.yml` to the repo as the acting user; deletes handled; failures
      retried and audited; deploy never blocked; token never leaked.
- [ ] `misp_auto_push` ON records one deduped sighting per MISP-sourced IOC alert;
      OFF by default does nothing; no events created.
- [ ] TI enrichment cache TTL is tunable, the key carries a provider fingerprint,
      and reinit flushes the cache.
- [ ] Backend (`pytest`/`ruff`) and frontend (`vitest`/`lint`/`tsc -b`) all green;
      all 5 CI checks pass; new migrations apply cleanly; existing 139 frontend
      tests intact.
- [ ] A clean PR is open against `main` (no AI attribution); production untouched.

---

## 12. Open Questions

All resolved (see §3). Two items to confirm *in code during the build*, with the
documented default if unconfirmable:
- Team switcher header wiring — attach `X-CHAD-Team` only if backend consumes it;
  else keep context/cosmetic. (Default: cosmetic, don't break env scoping.)
- TI cache target — enrichment cache (`manager.py`) vs IOC-pull cache
  (`ioc_cache.py`). (Default: enrichment cache.)
