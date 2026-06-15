"""One-way git config-as-code sync (Feature C).

``GitSyncService`` wraps GitPython to push a single deployed rule's YAML to a
remote repo (clone → write → commit-as-author → push). It is intentionally
*one-way*: CHAD → git. There is no inbound import, no bidirectional merge, and
no promotion/PR flow here — those modes are reserved in ``Environment.gitops_mode``
but deliberately unimplemented (they could mutate live detection rules).

All methods are synchronous (GitPython shells out to ``git``); async callers run
them via ``asyncio.to_thread``. Tokens are injected only into the transient
clone URL and redacted from every log/error message.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from urllib.parse import quote, urlsplit, urlunsplit

from git import Actor, GitCommandError, Repo
from git.cmd import Git

logger = logging.getLogger(__name__)

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_CRED_RE = re.compile(r"(https?://)[^@/\s]+@")


class GitSyncError(Exception):
    """Raised when a git operation fails (message is already token-redacted)."""


def rule_slug(title: str) -> str:
    """Filesystem-safe slug for a rule filename (without extension)."""
    slug = _SLUG_RE.sub("-", (title or "").lower()).strip("-")
    return slug or "unnamed"


def rule_git_filename(title: str) -> str:
    """Stable ``<slug>.yml`` filename for a rule."""
    return f"{rule_slug(title)}.yml"


def redact_git_url(value: str | None) -> str:
    """Strip ``user:token@`` credentials from a URL/message before logging."""
    if not value:
        return ""
    return _URL_CRED_RE.sub(r"\1***@", value)


class GitSyncService:
    """Push/delete a single file in a remote git repo over HTTPS."""

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        token: str | None = None,
        author_name: str | None = None,
        author_email: str | None = None,
    ):
        self.repo_url = repo_url
        self.branch = branch or "main"
        self.token = token
        self.author_name = author_name or "CHAD"
        self.author_email = author_email or "chad@localhost"

    def _authed_url(self) -> str:
        """Inject the PAT into an https URL; non-http(s) URLs pass through."""
        if not self.token:
            return self.repo_url
        parts = urlsplit(self.repo_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return self.repo_url
        netloc = f"{quote(self.token, safe='')}@{parts.hostname}"
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )

    def _redact(self, msg: object) -> str:
        text = str(msg)
        if self.token:
            text = text.replace(self.token, "***")
        return redact_git_url(text)

    def _checkout_branch(self, repo: Repo) -> None:
        try:
            repo.git.checkout(self.branch)
        except GitCommandError:
            # Branch doesn't exist yet (new/empty repo) — create it.
            repo.git.checkout("-B", self.branch)

    def _push(self, repo: Repo) -> None:
        repo.git.push("origin", f"HEAD:refs/heads/{self.branch}")

    def test_connection(self) -> bool:
        """Verify the repo is reachable with the given credentials."""
        try:
            Git().ls_remote(self._authed_url())
            return True
        except GitCommandError as e:
            raise GitSyncError(
                f"Git connection failed: {self._redact(e)}"
            ) from None

    def push_file(self, file_path: str, content: str, commit_message: str) -> str:
        """Create/update ``file_path`` with ``content`` and push. Returns SHA."""
        author = Actor(self.author_name, self.author_email)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo = Repo.clone_from(self._authed_url(), tmp)
                self._checkout_branch(repo)

                abs_path = os.path.join(tmp, file_path)
                os.makedirs(os.path.dirname(abs_path) or tmp, exist_ok=True)
                with open(abs_path, "w", encoding="utf-8") as fh:
                    fh.write(content)

                repo.index.add([file_path])
                if not repo.is_dirty() and not repo.untracked_files:
                    # Content identical to what's already committed — nothing to do.
                    head = repo.head.commit.hexsha if repo.head.is_valid() else ""
                    return head
                commit = repo.index.commit(
                    commit_message, author=author, committer=author
                )
                self._push(repo)
                return commit.hexsha
        except GitCommandError as e:
            raise GitSyncError(f"Git push failed: {self._redact(e)}") from None

    def read_rules(self, subdir: str) -> dict[str, str]:
        """Clone the repo (read-only) and return ``{relpath: yaml content}`` for
        every ``*.yml`` / ``*.yaml`` under ``subdir``.

        Inbound/read-only counterpart of push_file, used by the gated GitOps
        import. Never writes or pushes — it only reads the remote state so an
        operator can review proposed rule changes before they touch CHAD.
        """
        out: dict[str, str] = {}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo = Repo.clone_from(self._authed_url(), tmp)
                self._checkout_branch(repo)
                base = os.path.join(tmp, subdir)
                if not os.path.isdir(base):
                    return out
                for root, _dirs, files in os.walk(base):
                    for fname in files:
                        if not fname.endswith((".yml", ".yaml")):
                            continue
                        abs_path = os.path.join(root, fname)
                        rel = os.path.relpath(abs_path, tmp)
                        try:
                            with open(abs_path, encoding="utf-8") as fh:
                                out[rel] = fh.read()
                        except OSError:
                            continue
                return out
        except GitCommandError as e:
            raise GitSyncError(f"Git read failed: {self._redact(e)}") from None

    def delete_file(self, file_path: str, commit_message: str) -> str | None:
        """Remove ``file_path`` and push. No-op (returns None) if absent."""
        author = Actor(self.author_name, self.author_email)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo = Repo.clone_from(self._authed_url(), tmp)
                self._checkout_branch(repo)

                abs_path = os.path.join(tmp, file_path)
                if not os.path.exists(abs_path):
                    return None
                repo.index.remove([file_path], working_tree=True)
                commit = repo.index.commit(
                    commit_message, author=author, committer=author
                )
                self._push(repo)
                return commit.hexsha
        except GitCommandError as e:
            raise GitSyncError(f"Git delete failed: {self._redact(e)}") from None
