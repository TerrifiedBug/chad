# Plan 009 — Findings: Alert tenant isolation investigation

**Investigated**: 2026-06-15, against branch `advisor/implement-all-findings` (base `ccf9970`). Read-only; no production code changed.

## Verdict: (c) LATENT — alerts are not org-isolated, but the alert/index-pattern subsystem is effectively single-org by data model

Alerts carry **no organization association at all** — not on write, not on read, and the index patterns they are keyed by are themselves not org-scoped. So there is no "org A's alerts vs org B's alerts" distinction in the data model to leak across. This is **not an active cross-tenant read bug today** (there is nothing to isolate yet); it is a **latent architecture gap**: the multi-tenancy foundation (F4) that exists for some entities does **not** extend to index patterns or alerts. It becomes an active data-isolation risk the moment the product onboards multiple orgs and expects their alerts to be separated.

## Evidence (the five questions)

1. **Index topology** — alerts are stored per *log source*, not per *org*. `alerts.py:323-325`: `get_alerts_index_name(index_suffix) -> f"chad-alerts-{index_suffix}"`. The suffix is the index pattern, not an org id. List defaults to `index_pattern="chad-alerts-*"` (`api/alerts.py:119`), i.e. all sources.

2. **Write-time org tagging** — none. `alerts.py:358-423` `create_alert` builds the alert document with `alert_id, rule_id, rule_title, severity, tags, status, log_document, created_at, updated_at` (+ optional `ti_enrichment`/`ioc_matches`). **No `org_id`/`organization_id` field is written.**

3. **Read-time scoping** — none. `grep` for `org_id|organization|get_org_id` in `api/alerts.py` and `services/alerts.py` returns **nothing**. `AlertService.get_alerts` (`alerts.py:518`) filters only on `status`/`severity`/`rule_id`/`owner_id` (`alerts.py:538-540`). No org/team term is added, and org context (`app.core.org_context.get_org_id`) is never consulted on the alert path.

4. **Index patterns are not org-scoped either** — `models/index_pattern.py:32-99`: columns are `name` (unique), `pattern` (unique), `percolator_index` (unique), health settings, `auth_token_encrypted`, `allowed_ips`, etc. **No `org_id`/`team_id` column.** Since alerts are keyed by index-pattern suffix and index patterns are global, there is no org boundary to inherit. The SQL helpers `apply_org_scope`/`apply_team_scope` (`services/org_scope.py:21`, `services/team_scope.py:13`) are applied to other models (e.g. Rules, per `tests/services/test_multitenancy.py`) but not to `IndexPattern` or alerts.

5. **Single-org reality** — `DEFAULT_ORG_ID` / `run_with_org` / `set_org_id` appear nowhere in the alert flow. Multi-tenancy (F4) is a foundation (org context, host→org resolution, org-scoped *rules*) that has **not** been wired through index patterns or the detection/alert subsystem. In practice the alert subsystem is global / single-org.

## Detail, IOC matches, and the live feed share the property

IOC matches and the websocket live feed read the same `chad-alerts-*` indices via the same `AlertService` query path, so they inherit the same (absence of) scoping. Any future fix must cover all three, not just the list endpoint.

## Test coverage gap

`tests/services/test_multitenancy.py` covers org context, host→org resolution, and SQL `apply_org_scope` — but **no alert/index-pattern isolation coverage**, because there is nothing to isolate yet. If alert-level multi-tenancy is implemented, isolation tests must be added.

## Recommended follow-up (only if/when alerts must be org-isolated)

This is an architecture/product decision, deliberately **not** auto-implemented (high blast radius, touches the data model + the detection hot path + a backfill of existing untagged data). If the product roadmap requires per-org alert isolation, scope a dedicated plan (suggested number **011**) with these parts:

1. **Data model**: add `org_id` to `IndexPattern` (and/or a tenant key) — index patterns are the natural org boundary since alerts derive from them. Default existing rows to `DEFAULT_ORG_ID` (mirror the NULL-org-admits-default convention already encoded in `apply_org_scope`, see `test_apply_org_scope_includes_null_for_default`).
2. **Write path**: stamp `org_id` into the alert document in `create_alert` (`alerts.py:358`), derived from the alert's index pattern. Add `org_id` to `ALERTS_MAPPING`.
3. **Read path**: add an OpenSearch scope helper analogous to the SQL one — e.g. `apply_org_scope_opensearch(must: list, org_id)` appending `{"term": {"org_id.keyword": org_id}}` (admitting the default/legacy bucket). Inject it in `AlertService.get_alerts`/`get_alerts_cached` from the caller's org context — and in IOC matches + the websocket feed.
4. **Backfill**: existing alert documents have no `org_id`; decide on a reindex/backfill or a default-org fallback in the query.
5. **Tests**: extend `test_multitenancy.py` with a two-org alert-isolation case (org A cannot read org B's alerts).

**Open questions for the maintainer**: Is per-org alert isolation actually a product requirement, or are orgs a coarser construct that intentionally shares the detection/alert plane? Are index patterns meant to be per-org or shared infrastructure? The answer determines whether plan 011 is needed at all.

## Status

No production code changed by this spike. `plans/README.md` updated to mark 009 DONE. No plan 011 created — it is gated on the maintainer's answer to the open questions above.
