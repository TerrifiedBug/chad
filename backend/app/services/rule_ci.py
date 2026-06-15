"""
Detection-as-Code CI service.

Runs a set of independent, gracefully-degrading checks over a single Sigma rule
to produce a CIReport — the detection-engineering analogue of a lint + test +
coverage pipeline:

  1. lint            -> Sigma syntax / schema validation (pySigma)
  2. field_validation -> referenced fields exist in the index mapping or have a
                         field mapping configured
  3. fp_backtest     -> run the rule against recent historical logs and flag it
                         as noisy when the match count exceeds a threshold
  4. coverage        -> does the rule map to at least one ATT&CK technique?

Each check returns ``pass`` / ``warn`` / ``fail`` (or ``skipped`` when a
dependency such as OpenSearch is unavailable). The aggregate ``passed`` flag is
True only when no check ended in ``fail`` — warnings and skips do not block.

This mirrors the existing rule-testing flow (sigma_service + run_historical_test
+ resolve_mappings + attack tag parsing) rather than re-implementing any of it.
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import yaml
from opensearchpy import OpenSearch
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import RuleAttackMapping
from app.models.index_pattern import IndexPattern
from app.services.attack_sync import extract_attack_tags
from app.services.field_mapping import resolve_mappings
from app.services.opensearch import get_index_fields
from app.services.sigma import sigma_service

logger = logging.getLogger(__name__)

# Check status constants (kept as plain strings for easy JSON serialization).
STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"

# Default noise threshold for the FP backtest: more matches than this over the
# backtest window flags the rule as too noisy. Callers can override per request.
DEFAULT_FP_THRESHOLD = 1000

# How far back the FP backtest scans by default (days).
DEFAULT_BACKTEST_DAYS = 7


@dataclass
class CICheck:
    """Result of a single independent CI check."""

    name: str
    status: str  # one of STATUS_PASS / STATUS_WARN / STATUS_FAIL / STATUS_SKIPPED
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CIReport:
    """Aggregate of all CI checks for one rule."""

    passed: bool
    checks: list[CICheck]
    summary: str


@dataclass
class CIOptions:
    """Tunable knobs for a CI run.

    fp_threshold: match count above which the FP backtest is flagged.
    backtest_days: how far back the backtest scans.
    run_backtest: allow callers to skip the (potentially expensive) backtest.
    """

    fp_threshold: int = DEFAULT_FP_THRESHOLD
    backtest_days: int = DEFAULT_BACKTEST_DAYS
    run_backtest: bool = True


def _aggregate(checks: list[CICheck]) -> CIReport:
    """Roll individual checks into a CIReport.

    ``passed`` is True only when no check failed. Warnings and skips are
    advisory and never block. The summary is a short, human-readable tally.
    """
    failed = [c for c in checks if c.status == STATUS_FAIL]
    warned = [c for c in checks if c.status == STATUS_WARN]
    skipped = [c for c in checks if c.status == STATUS_SKIPPED]
    passed = len(failed) == 0

    parts: list[str] = []
    parts.append(f"{len([c for c in checks if c.status == STATUS_PASS])} passed")
    if warned:
        parts.append(f"{len(warned)} warning{'s' if len(warned) != 1 else ''}")
    if failed:
        parts.append(f"{len(failed)} failed")
    if skipped:
        parts.append(f"{len(skipped)} skipped")

    verdict = "CI passed" if passed else "CI failed"
    summary = f"{verdict} — {', '.join(parts)}."
    return CIReport(passed=passed, checks=checks, summary=summary)


def _check_lint(yaml_content: str) -> tuple[CICheck, Any]:
    """Sigma syntax/schema validation. Returns (check, translation_result).

    The translation result is reused by downstream checks (field extraction)
    so we don't parse the rule twice.
    """
    result = sigma_service.translate_and_validate(yaml_content)
    if result.success:
        return (
            CICheck(
                name="lint",
                status=STATUS_PASS,
                detail="Sigma rule parsed and translated successfully.",
            ),
            result,
        )

    errors = result.errors or []
    messages = "; ".join(e.message for e in errors) or "Unknown parse error"
    return (
        CICheck(
            name="lint",
            status=STATUS_FAIL,
            detail=f"Sigma validation failed: {messages}",
            data={
                "errors": [
                    {"type": e.type, "message": e.message, "line": e.line, "field": e.field}
                    for e in errors
                ]
            },
        ),
        result,
    )


async def _check_field_validation(
    db: AsyncSession,
    os_client: OpenSearch | None,
    index_pattern: IndexPattern | None,
    sigma_fields: list[str],
) -> CICheck:
    """Verify referenced fields exist in the index mapping or have a mapping.

    Mirrors the per-rule logic in ``_evaluate_rule_eligibility`` / the validate
    endpoint: a field is satisfied when it maps to (or directly is) a field
    present in the index mapping. Degrades to ``skipped`` when OpenSearch or the
    index pattern is unavailable, since we can't enumerate the index fields.
    """
    if not sigma_fields:
        return CICheck(
            name="field_validation",
            status=STATUS_PASS,
            detail="Rule references no fields to validate.",
        )

    if index_pattern is None:
        return CICheck(
            name="field_validation",
            status=STATUS_SKIPPED,
            detail="No index pattern associated; cannot validate fields.",
        )

    if os_client is None:
        return CICheck(
            name="field_validation",
            status=STATUS_SKIPPED,
            detail="OpenSearch unavailable; skipped field existence check.",
        )

    try:
        index_fields = set(
            get_index_fields(os_client, index_pattern.pattern, include_multi_fields=True)
        )
    except Exception as exc:  # noqa: BLE001 - degrade gracefully on OS errors
        logger.debug("field_validation: get_index_fields failed: %s", exc)
        return CICheck(
            name="field_validation",
            status=STATUS_SKIPPED,
            detail=f"Could not read index mapping: {exc}",
        )

    if not index_fields:
        # Pattern matched no indices / empty mapping — can't assert anything.
        return CICheck(
            name="field_validation",
            status=STATUS_SKIPPED,
            detail=(
                f"Index pattern '{index_pattern.pattern}' returned no field "
                "mappings; skipped field existence check."
            ),
        )

    mappings = await resolve_mappings(db, sigma_fields, index_pattern.id)

    unmapped: list[str] = []
    for field_name in sigma_fields:
        mapped = mappings.get(field_name)
        if mapped is not None and mapped in index_fields:
            continue
        if field_name in index_fields:
            continue
        unmapped.append(field_name)

    if unmapped:
        return CICheck(
            name="field_validation",
            status=STATUS_FAIL,
            detail=(
                f"{len(unmapped)} field(s) not present in index "
                f"'{index_pattern.pattern}' and not mapped: {', '.join(sorted(unmapped))}"
            ),
            data={"unmapped_fields": sorted(unmapped)},
        )

    return CICheck(
        name="field_validation",
        status=STATUS_PASS,
        detail=f"All {len(sigma_fields)} referenced field(s) resolve in the index.",
    )


async def _check_fp_backtest(
    db: AsyncSession,
    os_client: OpenSearch | None,
    rule_yaml: str,
    index_pattern: IndexPattern | None,
    options: CIOptions,
) -> CICheck:
    """Run the rule over recent historical logs and flag noisy rules.

    Reuses the same translate -> resolve mappings -> count pipeline as
    ``run_historical_test`` but counts only (no document hydration), since CI
    only cares about volume. Degrades to ``skipped`` whenever OpenSearch / the
    index pattern is unavailable or the rule can't be translated (the lint check
    already surfaces translation failures, so we don't double-report them).
    """
    if not options.run_backtest:
        return CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail="Backtest disabled for this run.",
        )

    if os_client is None:
        return CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail="OpenSearch unavailable; skipped false-positive backtest.",
        )

    if index_pattern is None:
        return CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail="No index pattern associated; skipped backtest.",
        )

    # Translate the rule, applying field mappings so the query uses real fields.
    translation = sigma_service.translate_and_validate(rule_yaml)
    if not translation.success or translation.query is None:
        return CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail="Rule could not be translated; backtest skipped.",
        )

    sigma_fields = list(translation.fields or set())
    if sigma_fields:
        resolved = await resolve_mappings(db, sigma_fields, index_pattern.id)
        field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}
        if field_mappings_dict:
            mapped = sigma_service.translate_with_mappings(rule_yaml, field_mappings_dict)
            if mapped.success and mapped.query is not None:
                translation = mapped

    inner_query = translation.query.get("query", translation.query)

    end_date = datetime.now(UTC)
    start_date = end_date - timedelta(days=options.backtest_days)

    # Combine the Sigma query with a time-range filter (same shape as
    # run_historical_test). Count-only — we don't hydrate documents.
    combined_query = {
        "query": {
            "bool": {
                "must": [inner_query],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_date.isoformat(),
                                "lte": end_date.isoformat(),
                            }
                        }
                    }
                ],
            }
        }
    }

    try:
        count_result = os_client.count(index=index_pattern.pattern, body=combined_query)
        match_count = count_result.get("count", 0)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully on OS errors
        logger.debug("fp_backtest: count query failed: %s", exc)
        return CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail=f"Backtest query failed: {exc}",
        )

    data = {
        "match_count": match_count,
        "threshold": options.fp_threshold,
        "window_days": options.backtest_days,
    }

    if match_count > options.fp_threshold:
        return CICheck(
            name="fp_backtest",
            status=STATUS_WARN,
            detail=(
                f"Rule matched {match_count} document(s) over the last "
                f"{options.backtest_days} day(s), exceeding the noise threshold "
                f"of {options.fp_threshold}. Consider tightening the detection."
            ),
            data=data,
        )

    return CICheck(
        name="fp_backtest",
        status=STATUS_PASS,
        detail=(
            f"Rule matched {match_count} document(s) over the last "
            f"{options.backtest_days} day(s), within the noise threshold "
            f"of {options.fp_threshold}."
        ),
        data=data,
    )


async def _check_coverage(
    db: AsyncSession,
    rule_yaml: str,
    rule_id: UUID | None,
) -> CICheck:
    """Does the rule map to at least one ATT&CK technique?

    Prefers persisted rule->technique mappings when a stored rule id is given
    (the source of truth used by the coverage matrix); otherwise falls back to
    parsing ``attack.t*`` tags directly out of the YAML so ad-hoc (unsaved)
    rules are still covered. A rule with no techniques is a warning, not a
    failure — coverage is advisory.
    """
    technique_ids: list[str] = []

    if rule_id is not None:
        result = await db.execute(
            select(func.count())
            .select_from(RuleAttackMapping)
            .where(RuleAttackMapping.rule_id == rule_id)
        )
        mapped_count = result.scalar_one() or 0
        if mapped_count > 0:
            return CICheck(
                name="coverage",
                status=STATUS_PASS,
                detail=f"Rule maps to {mapped_count} ATT&CK technique(s).",
                data={"technique_count": mapped_count},
            )

    # Fall back to (or, for ad-hoc rules, rely on) tags in the YAML.
    try:
        parsed = yaml.safe_load(rule_yaml)
        tags = parsed.get("tags", []) if isinstance(parsed, dict) else []
        technique_ids = extract_attack_tags(tags if isinstance(tags, list) else [])
    except yaml.YAMLError:
        technique_ids = []

    if technique_ids:
        return CICheck(
            name="coverage",
            status=STATUS_PASS,
            detail=f"Rule tags reference {len(technique_ids)} ATT&CK technique(s).",
            data={"technique_ids": technique_ids},
        )

    return CICheck(
        name="coverage",
        status=STATUS_WARN,
        detail=(
            "Rule maps to no ATT&CK techniques. Add attack.* tags to improve "
            "coverage visibility."
        ),
    )


async def run_ci(
    db: AsyncSession,
    os_client: OpenSearch | None,
    rule_yaml: str,
    index_pattern_id: UUID | None,
    options: CIOptions | None = None,
    rule_id: UUID | None = None,
) -> CIReport:
    """Run the full Detection-as-Code CI pipeline over a single rule.

    Args:
        db: Database session.
        os_client: OpenSearch client, or None when unavailable (OS-dependent
            checks then degrade to ``skipped`` rather than failing).
        rule_yaml: The Sigma rule YAML to check.
        index_pattern_id: Index pattern the rule targets (for field validation
            and the backtest). May be None for a pure syntax check.
        options: Tunable thresholds; defaults applied when omitted.
        rule_id: Optional stored-rule id, used to read persisted ATT&CK mappings
            for the coverage check.

    Returns:
        A CIReport aggregating every check.
    """
    options = options or CIOptions()

    # Resolve the index pattern once (shared by field validation + backtest).
    index_pattern: IndexPattern | None = None
    if index_pattern_id is not None:
        result = await db.execute(
            select(IndexPattern).where(IndexPattern.id == index_pattern_id)
        )
        index_pattern = result.scalar_one_or_none()

    # 1. Lint — also yields the parsed translation reused below.
    lint_check, translation = _check_lint(rule_yaml)
    sigma_fields = (
        list(translation.fields or set()) if getattr(translation, "success", False) else []
    )

    # 2. Field validation.
    field_check = await _check_field_validation(db, os_client, index_pattern, sigma_fields)

    # 3. FP backtest. Skip outright if lint failed — there's no usable query.
    if lint_check.status == STATUS_FAIL:
        backtest_check = CICheck(
            name="fp_backtest",
            status=STATUS_SKIPPED,
            detail="Skipped because the rule failed linting.",
        )
    else:
        backtest_check = await _check_fp_backtest(
            db, os_client, rule_yaml, index_pattern, options
        )

    # 4. ATT&CK coverage.
    coverage_check = await _check_coverage(db, rule_yaml, rule_id)

    return _aggregate([lint_check, field_check, backtest_check, coverage_check])
