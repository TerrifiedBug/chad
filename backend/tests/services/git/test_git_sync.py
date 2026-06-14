"""Tests for GitSyncService against a real local bare repo (Feature C)."""

import subprocess

import pytest

from app.services.git.git_sync import (
    GitSyncError,
    GitSyncService,
    redact_git_url,
    rule_git_filename,
    rule_slug,
)


def _run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def _init_bare_with_main(tmp_path):
    """Create a bare repo seeded with an initial commit on ``main``."""
    bare = tmp_path / "remote.git"
    _run("git", "init", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _run("git", "clone", str(bare), str(seed))
    (seed / "README.md").write_text("seed")
    _run("git", "-C", str(seed), "add", ".")
    _run(
        "git", "-C", str(seed),
        "-c", "user.email=seed@chad.local", "-c", "user.name=seed",
        "commit", "-m", "init",
    )
    _run("git", "-C", str(seed), "push", "origin", "main")
    return bare


def _read_file_from_bare(tmp_path, bare, rel_path):
    check = tmp_path / "check"
    _run("git", "clone", str(bare), str(check))
    target = check / rel_path
    return target.read_text() if target.exists() else None


# --- pure helpers ---------------------------------------------------------- #
def test_rule_slug():
    assert rule_slug("Suspicious PowerShell!!") == "suspicious-powershell"
    assert rule_slug("  ") == "unnamed"
    assert rule_slug("A/B::C") == "a-b-c"


def test_rule_git_filename():
    assert rule_git_filename("My Rule") == "my-rule.yml"


def test_redact_git_url():
    assert redact_git_url("https://ghp_secret@github.com/o/r.git") == (
        "https://***@github.com/o/r.git"
    )
    assert redact_git_url("https://github.com/o/r.git") == (
        "https://github.com/o/r.git"
    )
    assert redact_git_url(None) == ""


def test_authed_url_injects_token():
    svc = GitSyncService("https://github.com/o/r.git", token="ghp_x")
    assert svc._authed_url() == "https://ghp_x@github.com/o/r.git"


def test_authed_url_passthrough_for_file_scheme():
    svc = GitSyncService("file:///tmp/x.git", token="ghp_x")
    assert svc._authed_url() == "file:///tmp/x.git"


def test_redact_hides_token_in_message():
    svc = GitSyncService("https://h/r.git", token="ghp_supersecret")
    assert "ghp_supersecret" not in svc._redact("boom ghp_supersecret boom")


# --- real git operations --------------------------------------------------- #
def test_push_file_commits_and_pushes(tmp_path):
    bare = _init_bare_with_main(tmp_path)
    svc = GitSyncService(repo_url=f"file://{bare}", branch="main",
                         author_name="CHAD", author_email="chad@local")

    sha = svc.push_file("production/rule.yml", "detection: test\n", "add rule")

    assert sha
    assert _read_file_from_bare(tmp_path, bare, "production/rule.yml") == (
        "detection: test\n"
    )


def test_push_file_updates_existing(tmp_path):
    bare = _init_bare_with_main(tmp_path)
    svc = GitSyncService(repo_url=f"file://{bare}", branch="main")
    svc.push_file("production/rule.yml", "v1\n", "add")
    svc.push_file("production/rule.yml", "v2\n", "update")
    assert _read_file_from_bare(tmp_path, bare, "production/rule.yml") == "v2\n"


def test_delete_file(tmp_path):
    bare = _init_bare_with_main(tmp_path)
    svc = GitSyncService(repo_url=f"file://{bare}", branch="main")
    svc.push_file("production/rule.yml", "x\n", "add")
    svc.delete_file("production/rule.yml", "remove")
    assert _read_file_from_bare(tmp_path, bare, "production/rule.yml") is None


def test_delete_missing_file_is_noop(tmp_path):
    bare = _init_bare_with_main(tmp_path)
    svc = GitSyncService(repo_url=f"file://{bare}", branch="main")
    assert svc.delete_file("production/never.yml", "remove") is None


def test_test_connection_ok(tmp_path):
    bare = _init_bare_with_main(tmp_path)
    svc = GitSyncService(repo_url=f"file://{bare}", branch="main")
    assert svc.test_connection() is True


def test_test_connection_failure(tmp_path):
    svc = GitSyncService(repo_url=f"file://{tmp_path}/does-not-exist.git")
    with pytest.raises(GitSyncError):
        svc.test_connection()
