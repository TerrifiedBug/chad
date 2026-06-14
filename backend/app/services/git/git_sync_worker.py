"""Enqueue + drain logic for one-way git sync (Feature C).

``enqueue_git_sync_for_deploy`` is called from the deploy apply path as a
non-blocking side-effect: it only adds a ``GitSyncJob`` row (the caller's
transaction commits it). ``process_git_sync_jobs`` is the leader-elected
scheduler task that drains the queue with bounded backoff. A git/network
failure therefore never blocks or fails a deploy — the deploy completes and the
commit catches up (or is surfaced as a failed job after retries).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_with_fallback
from app.models.environment import Environment
from app.models.git_sync_job import GitSyncJob
from app.models.rule import Rule
from app.models.user import User
from app.services.git.git_sync import (
    GitSyncError,
    GitSyncService,
    rule_git_filename,
)

logger = logging.getLogger(__name__)

# Retry backoff (seconds) indexed by attempt number. After max_attempts the job
# is marked failed.
_BACKOFF_SECONDS = [30, 120, 600]

# Only ``push`` is implemented; other modes are reserved but inert.
GITOPS_PUSH = "push"


def _env_git_enabled(env: Environment | None) -> bool:
    return bool(
        env is not None
        and env.gitops_mode == GITOPS_PUSH
        and env.git_repo_url
        and env.git_token_encrypted
    )


async def enqueue_git_sync_for_deploy(
    db: AsyncSession,
    rule: Rule,
    environment: Environment | None,
    yaml_content: str,
    actor_id=None,
) -> GitSyncJob | None:
    """Queue a commit of ``rule``'s YAML to ``environment``'s repo.

    No-op unless the env is in ``push`` mode with a repo + token. Adds the row to
    the current session WITHOUT committing (the deploy txn persists it). Never
    raises — a failure here must not break the deploy.
    """
    if not _env_git_enabled(environment):
        return None
    assert environment is not None  # narrowed by _env_git_enabled

    try:
        # Stable filename, set once and reused across renames.
        if not rule.git_path:
            rule.git_path = rule_git_filename(rule.title)
        file_path = f"{environment.slug}/{rule.git_path}"

        author_name = None
        author_email = None
        if actor_id is not None:
            user = (
                await db.execute(select(User).where(User.id == actor_id))
            ).scalar_one_or_none()
            if user is not None:
                author_email = user.email
                author_name = getattr(user, "full_name", None) or user.email

        job = GitSyncJob(
            environment_id=environment.id,
            rule_id=rule.id,
            action="commit",
            file_path=file_path,
            yaml_content=yaml_content,
            commit_message=f"Deploy rule '{rule.title}' to {environment.name}",
            author_name=author_name,
            author_email=author_email,
            status="pending",
            next_retry_at=datetime.now(UTC),
        )
        db.add(job)
        return job
    except Exception as e:  # pragma: no cover - defensive, never break deploy
        logger.warning("Failed to enqueue git sync for rule %s: %s", rule.id, e)
        return None


async def enqueue_git_delete(
    db: AsyncSession,
    rule: Rule,
    environment: Environment,
) -> GitSyncJob | None:
    """Queue a ``git rm`` of ``rule``'s file from ``environment``'s repo."""
    if not _env_git_enabled(environment):
        return None
    if not rule.git_path:
        return None
    job = GitSyncJob(
        environment_id=environment.id,
        rule_id=rule.id,
        action="delete",
        file_path=f"{environment.slug}/{rule.git_path}",
        yaml_content=None,
        commit_message=f"Remove rule '{rule.title}' from {environment.name}",
        status="pending",
        next_retry_at=datetime.now(UTC),
    )
    db.add(job)
    return job


def _build_service(env: Environment, job: GitSyncJob) -> GitSyncService:
    token = decrypt_with_fallback(env.git_token_encrypted)
    return GitSyncService(
        repo_url=env.git_repo_url or "",
        branch=env.git_branch or "main",
        token=token,
        author_name=job.author_name,
        author_email=job.author_email,
    )


async def _run_job(db: AsyncSession, job: GitSyncJob) -> None:
    """Execute one job; update status with bounded backoff on failure."""
    env = (
        await db.execute(
            select(Environment).where(Environment.id == job.environment_id)
        )
    ).scalar_one_or_none()
    if env is None or not _env_git_enabled(env):
        # Env deleted or git disabled since enqueue — drop the job.
        job.status = "done"
        job.last_error = "environment git sync no longer configured"
        return

    service = _build_service(env, job)
    try:
        if job.action == "delete":
            await asyncio.to_thread(
                service.delete_file, job.file_path, job.commit_message
            )
        else:
            await asyncio.to_thread(
                service.push_file,
                job.file_path,
                job.yaml_content or "",
                job.commit_message,
            )
        job.status = "done"
        job.last_error = None
        job.next_retry_at = None
    except (GitSyncError, Exception) as e:  # noqa: BLE001 - record + retry
        job.attempts += 1
        job.last_error = str(e)[:2000]
        if job.attempts >= job.max_attempts:
            job.status = "failed"
            job.next_retry_at = None
            logger.error(
                "Git sync job %s permanently failed after %d attempts: %s",
                job.id,
                job.attempts,
                e,
            )
        else:
            delay = _BACKOFF_SECONDS[min(job.attempts - 1, len(_BACKOFF_SECONDS) - 1)]
            job.status = "pending"
            job.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay)
            logger.warning(
                "Git sync job %s failed (attempt %d), retrying in %ds: %s",
                job.id,
                job.attempts,
                delay,
                e,
            )


async def process_git_sync_jobs(db: AsyncSession, limit: int = 50) -> int:
    """Drain due pending jobs. Returns the number processed."""
    now = datetime.now(UTC)
    due = (
        (
            await db.execute(
                select(GitSyncJob)
                .where(
                    GitSyncJob.status == "pending",
                    (GitSyncJob.next_retry_at.is_(None))
                    | (GitSyncJob.next_retry_at <= now),
                )
                .order_by(GitSyncJob.created_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    processed = 0
    for job in due:
        job.status = "running"
        await db.flush()
        await _run_job(db, job)
        await db.commit()
        processed += 1
    return processed
