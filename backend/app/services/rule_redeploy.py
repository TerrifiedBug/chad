"""Recompile and redeploy a rule's percolator query.

Used when something other than the rule's own YAML changes the compiled query —
most importantly a field-mapping edit. A deployed percolator stores the query
that was compiled at deploy time; if a Sigma field's target mapping later
changes, the live percolator keeps matching on the stale field until the rule is
recompiled and re-pushed. This mirrors the compile+deploy steps in the
``rules.deploy_rule`` endpoint so both paths produce identical percolator docs.
"""

import asyncio
import logging
from typing import Any

import yaml
from opensearchpy import OpenSearch
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule
from app.services.field_mapping import resolve_mappings
from app.services.percolator import PercolatorService
from app.services.sigma import sigma_service

logger = logging.getLogger(__name__)


async def redeploy_rule_to_percolator(
    db: AsyncSession,
    os_client: OpenSearch,
    rule: Rule,
    index_pattern: IndexPattern,
) -> dict[str, Any]:
    """Recompile ``rule`` with the current field mappings and overwrite its percolator doc.

    Only deployed, push-mode rules are redeployed; anything else is skipped.
    Never raises — returns a structured outcome dict so one failing rule does not
    abort a batch of redeploys.

    Returns: ``{"rule_id", "status": "redeployed"|"skipped"|"failed", ...}``.
    """
    rule_id = str(rule.id)

    # Only live, push-mode rules have a percolator document to refresh.
    if rule.deployed_at is None:
        return {"rule_id": rule_id, "status": "skipped", "reason": "not_deployed"}

    if app_settings.is_pull_only or index_pattern.mode != "push":
        return {"rule_id": rule_id, "status": "skipped", "reason": "pull_mode"}

    try:
        validation = sigma_service.translate_and_validate(rule.yaml_content)
        if not validation.success:
            return {"rule_id": rule_id, "status": "failed", "reason": "validation"}

        sigma_fields = list(validation.fields or set())
        field_mappings_dict: dict[str, str] = {}
        if sigma_fields:
            resolved = await resolve_mappings(db, sigma_fields, index_pattern.id)
            field_mappings_dict = {k: v for k, v in resolved.items() if v is not None}

            # Auto-correct mappings that point at text fields (same as deploy_rule).
            from app.services.field_type_detector import auto_correct_field_mapping

            corrected: dict[str, str] = {}
            for sigma_field, target_field in field_mappings_dict.items():
                corrected_field, _ = await asyncio.to_thread(
                    auto_correct_field_mapping, os_client, index_pattern.pattern, target_field
                )
                corrected[sigma_field] = corrected_field
            field_mappings_dict = corrected

        translation = sigma_service.translate_with_mappings(
            rule.yaml_content, field_mappings_dict or None
        )
        if not translation.success:
            return {"rule_id": rule_id, "status": "failed", "reason": "translation"}

        parsed_rule = yaml.safe_load(rule.yaml_content)
        tags = parsed_rule.get("tags", []) if isinstance(parsed_rule, dict) else []

        percolator = PercolatorService(os_client)
        percolator_index = percolator.get_percolator_index_name(index_pattern.pattern)
        # Sigma returns {"query": {"query_string": ...}}; percolator needs the inner query.
        percolator_query = translation.query.get("query", translation.query)

        def _deploy() -> None:
            percolator.ensure_percolator_index(percolator_index, index_pattern.pattern)
            percolator.deploy_rule(
                percolator_index=percolator_index,
                rule_id=rule_id,
                query=percolator_query,
                title=rule.title,
                severity=rule.severity,
                tags=tags,
            )

        await asyncio.to_thread(_deploy)

        logger.info(
            "Redeployed rule %s to percolator %s after field-mapping change",
            rule_id,
            percolator_index,
        )
        return {"rule_id": rule_id, "status": "redeployed", "percolator_index": percolator_index}
    except Exception as e:
        logger.warning("Failed to redeploy rule %s after field-mapping change: %s", rule_id, e)
        return {"rule_id": rule_id, "status": "failed", "reason": type(e).__name__}
