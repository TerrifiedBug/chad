# Plan 009 (SPIKE): Investigate whether alert listing enforces org/team tenant isolation

> **Executor instructions**: This is an INVESTIGATION/spike, not a code change.
> Your deliverable is a written report (see "Deliverable"). Do **not** modify
> the alert query logic or any tenant-scoping behavior in this plan — if you
> find a gap, document it and recommend a fix for review. If a "STOP condition"
> occurs, stop and report. When done, update this plan's row in
> `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/services/alerts.py backend/app/api/alerts.py backend/app/services/org_scope.py`
> If these changed materially, note it in your report.

## Status

- **Priority**: P2 (security investigation — resolve the uncertainty before it becomes a finding either way)
- **Effort**: S (investigate)
- **Risk**: LOW (read-only investigation)
- **Depends on**: none
- **Category**: security (investigate)
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

CHAD is multi-tenant: there is an org/team foundation (`org_scope.py`, `team_scope.py`, host→org resolution, `test_multitenancy.py` titled "multi-tenancy foundation (F4)"). The SQL scope helpers `apply_org_scope(stmt, model, org_id)` and `apply_team_scope(stmt, model, user)` add tenant predicates to **SQLAlchemy** queries. But **alerts live in OpenSearch** (`chad-alerts-*`), not Postgres, and `AlertService.get_alerts` builds its OpenSearch query from `status` / `severity` / `rule_id` / `owner_id` only — there is **no visible org/team term**. If alerts from multiple orgs share an index and the query isn't org-scoped, a user in org A could enumerate org B's alerts. This may be fine (e.g. per-org indices, or F4 not yet covering alerts), or it may be a cross-tenant read gap. The point of this spike is to **answer the question with evidence** so it's either closed as safe or promoted to a concrete fix plan — not to guess.

## What we already know (starting evidence)

- `backend/app/services/org_scope.py:21` — `apply_org_scope(stmt, model, org_id)` (SQL only). `:38` — `can_access_org_resource(resource, org_id)`.
- `backend/app/services/team_scope.py:13` — `apply_team_scope(stmt, model, user)` (SQL only). `:25` — `can_access_resource(resource, user)`.
- `backend/app/services/alerts.py:518` — `AlertService.get_alerts(...)`; builds OpenSearch `must` clauses. Only `owner_id` adds a term (`alerts.py:538-540`). No org/team term observed.
- `backend/app/api/alerts.py:110` — `list_alerts` calls the service with `index_pattern="chad-alerts-*"` (default).
- `backend/tests/services/test_multitenancy.py` — covers org context, host→org, and SQL `apply_org_scope`; does **not** appear to cover alert (OpenSearch) tenant isolation.
- Org context plumbing exists: `app/core/org_context.py` (`get_org_id`, `set_org_id`, `run_with_org`), `app/services/host_to_org.py` (`resolve_org_id_from_host`).

## The questions to answer (with file:line evidence for each)

1. **Index topology**: Are alerts stored in a single shared index pattern across orgs, or per-org indices? Inspect how the alerts index name is derived (`AlertService.get_alerts_index_name`, `alerts.py:334`) and where alert documents are written (search `log_processor.py` / `alerts.py` for the index used on write). Does the index name incorporate an org id?
2. **Write-time org tagging**: When an alert is created, is an `org_id`/`organization_id` field written into the document? (Search the alert-creation path.)
3. **Read-time scoping**: Does any layer between the HTTP request and OpenSearch inject an org/team filter — middleware, `get_current_user`, the `index_pattern` chosen per request, or org context? Trace `list_alerts` → `AlertService.get_alerts`/`get_alerts_cached` and check whether org context (`get_org_id()`) is consulted anywhere.
4. **Detail & siblings**: Do `GET /alerts/{id}`, IOC matches (`api` for IOC), and the live alert feed (`websocket.py`) have the same property? (Same isolation question applies.)
5. **Single-org reality**: Is the deployment effectively single-org today (default org only), making this latent rather than active? (`DEFAULT_ORG_ID` usage.)

## Commands / tools you will need

- Code search only (read-only): `grep -rn`, reading files. No DB/OpenSearch mutation.
- Useful greps:
  - `grep -rn "org_id\|organization_id\|get_org_id\|index_pattern\|chad-alerts" backend/app/services/alerts.py backend/app/api/alerts.py backend/app/services/log_processor.py`
  - `grep -rn "get_alerts_index_name\|index_name" backend/app/services/alerts.py`
- If you want to confirm behavior dynamically, read `backend/tests/services/test_multitenancy.py` and `test_alerts.py` to see what isolation (if any) is asserted.

## Scope

**In scope**: reading code, reading tests, and writing a report. Optionally writing a **failing/characterization test** that demonstrates the current behavior (a test that asserts two orgs' alerts are/aren't separated) — but only if it does not require changing production code.

**Out of scope** (do NOT do in this plan):
- Modifying `AlertService.get_alerts`, the alert query, index routing, or any scoping behavior. A tenant-scoping change is security-sensitive and risks the default-org / legacy-NULL-org rows (see `test_apply_org_scope_includes_null_for_default`). It must be its own reviewed plan.
- Any change to `org_scope.py` / `team_scope.py`.

## Deliverable

Write `plans/009-findings.md` containing:
1. **Verdict**: one of — (a) Alerts ARE tenant-isolated (explain the mechanism with file:line); (b) Alerts are NOT isolated and this is an active cross-tenant read risk; (c) Latent — not isolated, but the deployment is single-org today so impact is currently nil.
2. **Evidence**: file:line answers to each of the five questions above.
3. **If (b) or (c)**: a recommended fix sketch and a proposed follow-up plan. The likely shape: an OpenSearch-query scope helper analogous to the SQL `apply_org_scope` — e.g. `apply_org_scope_opensearch(must: list, org_id)` that appends an `{"term": {"org_id.keyword": ...}}` filter (admitting NULL/default-org for legacy docs, mirroring the SQL helper's default-org handling) — plus the write-path change to tag alerts with `org_id`, plus characterization tests. List open questions and migration concerns (existing untagged alert documents).
4. **Test coverage gap**: note whether `test_multitenancy.py` should gain alert-isolation coverage.

## Done criteria

- [ ] `plans/009-findings.md` exists with a clear verdict (a/b/c) and file:line evidence for all five questions
- [ ] No production code changed (`git status` shows only `plans/` additions, plus an optional characterization test that doesn't require prod changes)
- [ ] If verdict is (b)/(c): a concrete follow-up fix plan is sketched in the findings
- [ ] `plans/README.md` status row updated (and a new plan added to the index if a fix is recommended)

## STOP conditions

Stop and report immediately (do not continue investigating further, surface it now) if:
- You confirm verdict (b) — alerts are shared across orgs with no read-time scoping and the deployment is genuinely multi-org. This is an active security gap; the operator needs to know before anything else proceeds.
- The investigation requires running queries against a production OpenSearch/DB (it should not — this is static analysis).

## Maintenance notes

- This spike intentionally produces a decision, not a fix. The fix (if needed) is deliberately a separate, reviewed plan because tenant-scoping changes are high-blast-radius and must preserve the default-org / legacy-NULL behavior already encoded in the SQL helpers.
- Whoever implements a fix should add the same isolation check to alert detail, IOC matches, and the websocket feed — not just the list endpoint.
