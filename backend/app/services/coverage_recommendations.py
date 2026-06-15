"""
Coverage-gap rule recommendation service.

Turns the ATT&CK coverage map into a prioritised "deploy these next" list.

The logic, in plain terms:

1. Ask the existing :mod:`attack_coverage` service for per-technique coverage so we
   never re-implement the count/aggregation rules that power the matrix.
2. Treat techniques with no deployed coverage (or only weak coverage) as gaps.
3. For each gap, look for concrete SigmaHQ rules that map to the uncovered
   technique by reusing :mod:`sigmahq` search — we search the repo for the
   technique tag (e.g. ``attack.t1059``) and keep the matching rules.
4. Prefer SigmaHQ rules that are *compatible* with the org's existing log
   sources / field mappings: a rule whose Sigma fields the org already maps is
   far cheaper to deploy than one that needs brand-new field translations.
5. Weight every gap by technique prevalence (how broad / commonly abused the
   tactic is) and by the severity of the rules that would close it, so the most
   valuable, lowest-effort gaps float to the top.

This module deliberately reuses the coverage and SigmaHQ services rather than
duplicating their query/file-access logic.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import AttackTechnique
from app.models.field_mapping import FieldMapping
from app.services.attack_coverage import attack_coverage_service
from app.services.sigmahq import RuleType, sigmahq_service

logger = logging.getLogger(__name__)


# A technique is "weakly covered" when it has rules but none deployed, or only a
# single deployed rule. These still surface as recommendations (lower priority)
# because single-rule coverage of a high-prevalence technique is fragile.
WEAK_DEPLOYED_THRESHOLD = 1

# How many SigmaHQ candidate rules to keep per gap in the response payload.
MAX_SUGGESTED_RULES = 5

# Severity ranking used to weight both gap priority and rule ordering.
_SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "unknown": 1,
}

# Coarse tactic-prevalence heuristic. ATT&CK has no per-technique "prevalence"
# field, so we approximate it from the tactic: tactics that attackers almost
# always touch (execution, persistence, defense evasion, ...) score higher than
# rarely-relevant ones. This keeps the ranking stable without external data.
_TACTIC_PREVALENCE = {
    "TA0001": 3,  # Initial Access
    "TA0002": 5,  # Execution
    "TA0003": 5,  # Persistence
    "TA0004": 4,  # Privilege Escalation
    "TA0005": 5,  # Defense Evasion
    "TA0006": 4,  # Credential Access
    "TA0007": 3,  # Discovery
    "TA0008": 3,  # Lateral Movement
    "TA0009": 3,  # Collection
    "TA0010": 3,  # Exfiltration
    "TA0011": 4,  # Command and Control
    "TA0040": 4,  # Impact
    "TA0042": 2,  # Resource Development
    "TA0043": 2,  # Reconnaissance
}
_DEFAULT_PREVALENCE = 3


@dataclass
class SuggestedRule:
    """A single SigmaHQ rule that would help close a coverage gap."""

    title: str
    path: str
    severity: str
    rule_type: str
    # True when every Sigma field the rule references is already mapped for at
    # least one of the org's index patterns (cheap to deploy, no new mappings).
    compatible: bool


@dataclass
class CoverageRecommendation:
    """A prioritised recommendation for one uncovered/weak technique."""

    technique_id: str
    technique_name: str
    tactic: str
    current_coverage: int  # number of deployed rules today (0 == fully uncovered)
    reason: str
    suggested_rule_titles: list[str]
    suggested_rules: list[SuggestedRule]
    priority: float


def _severity_weight(severity: str | None) -> int:
    return _SEVERITY_WEIGHT.get((severity or "unknown").lower(), 1)


def _extract_rule_fields(yaml_content: str) -> set[str]:
    """
    Pull the Sigma detection field names out of a rule's YAML.

    We only need the *keys* used inside ``detection`` selections (minus the
    ``condition`` meta key and Sigma field modifiers like ``|contains``) to
    decide whether the org already maps those fields. Parsing failures simply
    yield an empty set so the rule is treated as "needs new mappings".
    """
    try:
        parsed = yaml.safe_load(yaml_content)
    except Exception:
        return set()

    if not isinstance(parsed, dict):
        return set()

    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        return set()

    fields: set[str] = set()

    def _walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                # Strip Sigma field modifiers ("Image|endswith" -> "Image").
                base_field = str(key).split("|", 1)[0].strip()
                if base_field:
                    fields.add(base_field)
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    for key, value in detection.items():
        if key == "condition":
            continue
        _walk(value)

    return fields


async def _get_org_mapped_fields(db: AsyncSession) -> set[str]:
    """
    Build the set of Sigma fields the org already knows how to translate.

    These come from the per-index :class:`FieldMapping` rows — they represent
    the org's existing log sources / field schema. A SigmaHQ rule is considered
    "compatible" when all of its detection fields are present here.
    """
    result = await db.execute(select(FieldMapping.sigma_field))
    return {row[0] for row in result if row[0]}


def _candidate_rules_for_technique(
    technique_id: str,
    org_fields: set[str],
) -> list[SuggestedRule]:
    """
    Find SigmaHQ rules that map to ``technique_id`` and rank them by how
    deployable they are against the org's existing field mappings.

    Reuses :meth:`SigmaHQService.search_rules`, which already searches rule
    tags. ATT&CK technique IDs appear in Sigma tags as ``attack.t1059`` etc., so
    searching for the lowercase tag fragment surfaces the relevant rules.
    """
    if not sigmahq_service.is_repo_cloned():
        return []

    # Tag form used inside Sigma rules, e.g. "T1059.001" -> "attack.t1059.001".
    tag_query = f"attack.{technique_id.lower()}"

    candidates: list[SuggestedRule] = []
    seen_paths: set[str] = set()

    # Search across all three SigmaHQ rule directories so threat-hunting and
    # emerging-threats coverage is considered too, not just core detections.
    for rule_type in RuleType:
        try:
            matches = sigmahq_service.search_rules(
                tag_query, limit=50, rule_type=rule_type
            )
        except Exception as exc:  # pragma: no cover - defensive, repo IO
            logger.warning(
                "SigmaHQ search failed for %s (%s): %s",
                technique_id,
                rule_type.value,
                exc,
            )
            continue

        for match in matches:
            path = match.get("path")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)

            # Determine field compatibility from the rule body when we have org
            # mappings to compare against. If we can't read the rule we fall back
            # to "incompatible" (safer: it may need new mappings).
            compatible = False
            if org_fields:
                content = sigmahq_service.get_rule_content(path, rule_type)
                if content:
                    rule_fields = _extract_rule_fields(content)
                    # Compatible when the org already maps every field the rule
                    # references (and the rule actually references fields).
                    compatible = bool(rule_fields) and rule_fields.issubset(org_fields)

            candidates.append(
                SuggestedRule(
                    title=str(match.get("title") or path),
                    path=path,
                    severity=str(match.get("severity") or "unknown"),
                    rule_type=rule_type.value,
                    compatible=compatible,
                )
            )

    # Rank: compatible-first, then higher severity, then deterministic title.
    candidates.sort(
        key=lambda r: (
            0 if r.compatible else 1,
            -_severity_weight(r.severity),
            r.title.lower(),
        )
    )
    return candidates


def _build_reason(
    deployed: int,
    total: int,
    compatible_count: int,
    suggested_count: int,
) -> str:
    """Human-readable explanation of why this technique is recommended."""
    if total == 0:
        coverage_part = "No rules are mapped to this technique"
    elif deployed == 0:
        coverage_part = (
            f"{total} rule{'s' if total != 1 else ''} mapped but none deployed"
        )
    else:
        coverage_part = (
            f"Only {deployed} deployed rule{'s' if deployed != 1 else ''} cover it"
        )

    if suggested_count == 0:
        action_part = "no matching SigmaHQ rules found — consider authoring one"
    elif compatible_count > 0:
        action_part = (
            f"{compatible_count} SigmaHQ rule{'s' if compatible_count != 1 else ''} "
            "ready to deploy with your existing field mappings"
        )
    else:
        action_part = (
            f"{suggested_count} SigmaHQ rule{'s' if suggested_count != 1 else ''} "
            "available (may need new field mappings)"
        )

    return f"{coverage_part}; {action_part}."


async def recommend(
    db: AsyncSession,
    os_client_or_none: object | None,
    limit: int = 10,
) -> list[CoverageRecommendation]:
    """
    Produce a ranked list of coverage-gap rule recommendations.

    Args:
        db: Async DB session.
        os_client_or_none: OpenSearch client (unused today — coverage comes from
            the relational mappings — but accepted so callers can pass the active
            client without branching, mirroring other services' signatures).
        limit: Maximum number of recommendations to return.

    Returns:
        Recommendations sorted by descending priority. Only parent techniques are
        recommended (sub-technique counts are already aggregated into parents by
        the coverage service), keeping the list at a useful altitude.
    """
    # 1. Pull deployed-only coverage so "covered" means "actually detecting".
    coverage_response = await attack_coverage_service.get_coverage(db, deployed_only=True)
    coverage = coverage_response.coverage

    # 2. Load technique metadata (name/tactic) for parent techniques only.
    tech_result = await db.execute(
        select(AttackTechnique).where(AttackTechnique.is_subtechnique == False)  # noqa: E712
    )
    techniques = tech_result.scalars().all()

    if not techniques:
        return []

    # 3. Org field mappings drive SigmaHQ rule compatibility scoring.
    org_fields = await _get_org_mapped_fields(db)

    recommendations: list[CoverageRecommendation] = []

    for tech in techniques:
        stats = coverage.get(tech.id)
        deployed = stats.deployed if stats else 0
        total = stats.total if stats else 0

        # Only uncovered or weakly-covered techniques are gaps worth surfacing.
        if deployed > WEAK_DEPLOYED_THRESHOLD:
            continue

        candidates = _candidate_rules_for_technique(tech.id, org_fields)
        top_candidates = candidates[:MAX_SUGGESTED_RULES]
        compatible_count = sum(1 for c in candidates if c.compatible)

        # 4. Priority score. Higher == more valuable / lower effort.
        prevalence = _TACTIC_PREVALENCE.get(tech.tactic_id, _DEFAULT_PREVALENCE)
        # Fully uncovered techniques (deployed == 0) get the gap bonus; weakly
        # covered ones (deployed == 1) get a smaller nudge.
        gap_bonus = 4 if deployed == 0 else 1
        # Severity signal from the best available candidate rule.
        best_rule_weight = (
            max(_severity_weight(c.severity) for c in candidates) if candidates else 0
        )
        # Compatible rules are the cheapest wins, so weight them heavily.
        priority = (
            prevalence
            + gap_bonus
            + best_rule_weight
            + (3 * min(compatible_count, 3))
        )
        # Slight penalty when there's nothing to deploy (needs authoring effort).
        if not candidates:
            priority -= 2

        recommendations.append(
            CoverageRecommendation(
                technique_id=tech.id,
                technique_name=tech.name,
                tactic=tech.tactic_name,
                current_coverage=deployed,
                reason=_build_reason(deployed, total, compatible_count, len(candidates)),
                suggested_rule_titles=[c.title for c in top_candidates],
                suggested_rules=top_candidates,
                priority=float(priority),
            )
        )

    # 5. Highest priority first; tie-break on a stable technique ID ordering.
    recommendations.sort(key=lambda r: (-r.priority, r.technique_id))

    return recommendations[:limit]
