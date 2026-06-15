"""Gated bidirectional GitOps — inbound import (I6).

Reverses the historical push-only non-goal *safely* and only when explicitly
enabled (the ``gitops_inbound`` flag = the operator sign-off). Even when on,
inbound NEVER mutates live detections: it reads the remote repo, shows a
human-reviewable diff of proposed rule changes, and — on apply — stages changes
as UNDEPLOYED draft versions of existing rules. Those drafts still go through the
normal deploy/maker-checker flow to ever reach the percolator, so a git push can
never silently change what is live.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt
from app.models.environment import Environment
from app.models.rule import Rule, RuleVersion
from app.services.settings import get_setting, set_setting

logger = logging.getLogger(__name__)

INBOUND_FLAG_KEY = "gitops_inbound"


class GitImportError(Exception):
    pass


async def is_inbound_enabled(db: AsyncSession) -> bool:
    cfg = await get_setting(db, INBOUND_FLAG_KEY)
    return bool(cfg and cfg.get("enabled"))


async def set_inbound_enabled(db: AsyncSession, enabled: bool) -> bool:
    await set_setting(db, INBOUND_FLAG_KEY, {"enabled": bool(enabled)})
    return bool(enabled)


def _service_for_env(environment: Environment):
    # Imported lazily (like the scheduler's git worker) so importing this module
    # — and thus app startup — never requires GitPython; only an actual import
    # call does.
    from app.services.git.git_sync import GitSyncService

    if not environment.git_repo_url:
        raise GitImportError("This environment has no git repository configured")
    token = None
    if environment.git_token_encrypted:
        try:
            token = decrypt(environment.git_token_encrypted)
        except Exception:
            token = None
    return GitSyncService(
        repo_url=environment.git_repo_url,
        branch=environment.git_branch or "main",
        token=token,
    )


def _title_of(content: str) -> str | None:
    try:
        doc = yaml.safe_load(content)
        if isinstance(doc, dict):
            t = doc.get("title")
            return str(t) if t else None
    except yaml.YAMLError:
        return None
    return None


async def _ensure_enabled(db: AsyncSession) -> None:
    if not await is_inbound_enabled(db):
        raise GitImportError(
            "Inbound GitOps is disabled. An admin must enable it (gitops_inbound) "
            "to import rules from git."
        )


async def preview_import(db: AsyncSession, environment: Environment) -> dict:
    """Read the repo and classify each rule file vs CHAD (no writes).

    Each item: {path, title, status: new|modified|unchanged, rule_id?}.
    """
    await _ensure_enabled(db)
    service = _service_for_env(environment)
    files = service.read_rules("rules")

    items = []
    for path, content in files.items():
        title = _title_of(content)
        rule = None
        if path:
            rule = (
                await db.execute(select(Rule).where(Rule.git_path == path))
            ).scalar_one_or_none()
        if rule is None and title:
            rule = (await db.execute(select(Rule).where(Rule.title == title))).scalar_one_or_none()
        if rule is None:
            status = "new"
        elif rule.yaml_content.strip() != content.strip():
            status = "modified"
        else:
            status = "unchanged"
        items.append(
            {"path": path, "title": title, "status": status,
             "rule_id": str(rule.id) if rule else None}
        )
    return {"items": items, "total": len(items)}


async def apply_import(
    db: AsyncSession, environment: Environment, actor_id: uuid.UUID, paths: list[str]
) -> dict:
    """Stage selected modified files as UNDEPLOYED draft versions of their rules.

    Only existing rules are updated (new files are reported as skipped — creating
    a brand-new rule needs an index-pattern choice and is left to the operator).
    Deployment state is untouched; the draft must be deployed via the normal flow.
    """
    await _ensure_enabled(db)
    service = _service_for_env(environment)
    files = service.read_rules("rules")
    selected = set(paths)

    updated, skipped = [], []
    for path in selected:
        content = files.get(path)
        if content is None:
            skipped.append({"path": path, "reason": "not found in repo"})
            continue
        title = _title_of(content)
        rule = (await db.execute(select(Rule).where(Rule.git_path == path))).scalar_one_or_none()
        if rule is None and title:
            rule = (await db.execute(select(Rule).where(Rule.title == title))).scalar_one_or_none()
        if rule is None:
            skipped.append({"path": path, "reason": "no matching rule (new rules created manually)"})
            continue
        if rule.yaml_content.strip() == content.strip():
            skipped.append({"path": path, "reason": "unchanged"})
            continue
        # Stage as a new draft version. Deployment is NOT touched.
        next_version = (
            (await db.execute(
                select(func.max(RuleVersion.version_number)).where(RuleVersion.rule_id == rule.id)
            )).scalar() or 0
        ) + 1
        rule.yaml_content = content
        rule.git_path = path
        db.add(RuleVersion(
            rule_id=rule.id, version_number=next_version, yaml_content=content,
            changed_by=actor_id,
            change_reason=f"Imported from git ({environment.name}) at {datetime.now(UTC).isoformat()}",
        ))
        updated.append({"path": path, "rule_id": str(rule.id), "version": next_version})

    await db.commit()
    return {"updated": updated, "skipped": skipped}
