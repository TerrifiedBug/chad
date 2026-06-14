"""Tests for git sync enqueue + drain worker (Feature C)."""

import subprocess
from datetime import UTC, datetime

import pytest

from app.core.encryption import encrypt
from app.models.environment import Environment
from app.models.git_sync_job import GitSyncJob
from app.services.git.git_sync_worker import (
    enqueue_git_delete,
    enqueue_git_sync_for_deploy,
    process_git_sync_jobs,
)


def _run(*args):
    subprocess.run(args, check=True, capture_output=True)


def _init_bare_with_main(tmp_path):
    bare = tmp_path / "remote.git"
    _run("git", "init", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _run("git", "clone", str(bare), str(seed))
    (seed / "README.md").write_text("seed")
    _run("git", "-C", str(seed), "add", ".")
    _run(
        "git", "-C", str(seed),
        "-c", "user.email=s@chad.local", "-c", "user.name=s",
        "commit", "-m", "init",
    )
    _run("git", "-C", str(seed), "push", "origin", "main")
    return bare


async def _make_env(session, **kwargs):
    env = Environment(name=kwargs.pop("name", "Prod"), **kwargs)
    session.add(env)
    await session.commit()
    await session.refresh(env)
    return env


@pytest.mark.asyncio
async def test_process_commit_job_pushes(test_session, tmp_path):
    bare = _init_bare_with_main(tmp_path)
    env = await _make_env(
        test_session,
        gitops_mode="push",
        git_repo_url=f"file://{bare}",
        git_branch="main",
        git_token_encrypted=encrypt("tok"),
    )
    job = GitSyncJob(
        environment_id=env.id,
        action="commit",
        file_path=f"{env.slug}/rule.yml",
        yaml_content="detection: x\n",
        commit_message="add rule",
        status="pending",
        next_retry_at=datetime.now(UTC),
    )
    test_session.add(job)
    await test_session.commit()

    processed = await process_git_sync_jobs(test_session)

    assert processed == 1
    await test_session.refresh(job)
    assert job.status == "done"

    check = tmp_path / "check"
    _run("git", "clone", str(bare), str(check))
    assert (check / env.slug / "rule.yml").read_text() == "detection: x\n"


@pytest.mark.asyncio
async def test_process_failure_marks_failed_at_max(test_session, tmp_path):
    env = await _make_env(
        test_session,
        name="Bad",
        gitops_mode="push",
        git_repo_url=f"file://{tmp_path}/nope.git",
        git_branch="main",
        git_token_encrypted=encrypt("tok"),
    )
    job = GitSyncJob(
        environment_id=env.id,
        action="commit",
        file_path=f"{env.slug}/rule.yml",
        yaml_content="x\n",
        commit_message="add",
        status="pending",
        max_attempts=1,
        next_retry_at=datetime.now(UTC),
    )
    test_session.add(job)
    await test_session.commit()

    await process_git_sync_jobs(test_session)

    await test_session.refresh(job)
    assert job.status == "failed"
    assert job.attempts == 1
    assert job.last_error


@pytest.mark.asyncio
async def test_process_failure_retries_with_backoff(test_session, tmp_path):
    env = await _make_env(
        test_session,
        name="Retry",
        gitops_mode="push",
        git_repo_url=f"file://{tmp_path}/nope.git",
        git_branch="main",
        git_token_encrypted=encrypt("tok"),
    )
    job = GitSyncJob(
        environment_id=env.id,
        action="commit",
        file_path=f"{env.slug}/rule.yml",
        yaml_content="x\n",
        commit_message="add",
        status="pending",
        max_attempts=3,
        next_retry_at=datetime.now(UTC),
    )
    test_session.add(job)
    await test_session.commit()

    await process_git_sync_jobs(test_session)

    await test_session.refresh(job)
    assert job.status == "pending"
    assert job.attempts == 1
    assert job.next_retry_at is not None
    assert job.next_retry_at > datetime.now(UTC)


@pytest.mark.asyncio
async def test_enqueue_skips_non_push_env(test_session, test_rule):
    env = await _make_env(test_session, name="Off", gitops_mode="off")
    job = await enqueue_git_sync_for_deploy(test_session, test_rule, env, "yaml", None)
    assert job is None


@pytest.mark.asyncio
async def test_enqueue_creates_job_and_sets_git_path(test_session, test_rule, tmp_path):
    env = await _make_env(
        test_session,
        name="Prod",
        gitops_mode="push",
        git_repo_url=f"file://{tmp_path}/r.git",
        git_branch="main",
        git_token_encrypted=encrypt("tok"),
    )
    job = await enqueue_git_sync_for_deploy(
        test_session, test_rule, env, "yaml: 1", None
    )
    assert job is not None
    assert job.action == "commit"
    assert test_rule.git_path  # set on first sync
    assert job.file_path == f"{env.slug}/{test_rule.git_path}"
    assert job.yaml_content == "yaml: 1"


@pytest.mark.asyncio
async def test_enqueue_delete_requires_git_path(test_session, test_rule, tmp_path):
    env = await _make_env(
        test_session,
        name="Prod2",
        gitops_mode="push",
        git_repo_url=f"file://{tmp_path}/r.git",
        git_branch="main",
        git_token_encrypted=encrypt("tok"),
    )
    # No git_path yet → nothing to delete.
    test_rule.git_path = None
    assert await enqueue_git_delete(test_session, test_rule, env) is None
    # With a git_path → delete job created.
    test_rule.git_path = "my-rule.yml"
    job = await enqueue_git_delete(test_session, test_rule, env)
    assert job is not None and job.action == "delete"
