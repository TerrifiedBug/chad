"""
SigmaHQ integration service for managing the SigmaHQ rule repository.

Handles git operations (clone, pull) and file system access to rules.
"""
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SyncResult:
    success: bool
    message: str
    commit_hash: str | None = None
    rule_count: int | None = None
    error: str | None = None


class SigmaHQService:
    DEFAULT_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
    DEFAULT_BASE_PATH = Path("/data/sigmahq")

    def __init__(self, base_path: Path | None = None):
        self.base_path = base_path or self.DEFAULT_BASE_PATH

    def get_rules_directory(self) -> Path:
        """Get the path to the rules directory."""
        return self.base_path / "rules"

    def is_repo_cloned(self) -> bool:
        """Check if the SigmaHQ repository is already cloned."""
        git_dir = self.base_path / ".git"
        rules_dir = self.get_rules_directory()
        return git_dir.exists() and rules_dir.exists()

    def clone_repo(self, repo_url: str | None = None) -> SyncResult:
        """Clone the SigmaHQ repository."""
        url = repo_url or self.DEFAULT_REPO_URL

        if self.is_repo_cloned():
            return SyncResult(
                success=False,
                message="Repository already cloned",
                error="Repository already exists at target path",
            )

        try:
            self.base_path.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(self.base_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                return SyncResult(
                    success=False,
                    message="Clone failed",
                    error=result.stderr,
                )

            commit_hash = self.get_current_commit_hash()
            rule_count = self.count_rules()

            return SyncResult(
                success=True,
                message="Repository cloned successfully",
                commit_hash=commit_hash,
                rule_count=rule_count,
            )

        except subprocess.TimeoutExpired:
            return SyncResult(
                success=False,
                message="Clone timed out",
                error="Git clone operation timed out after 5 minutes",
            )
        except Exception as e:
            return SyncResult(
                success=False,
                message="Clone failed",
                error=str(e),
            )

    def pull_repo(self) -> SyncResult:
        """Pull latest changes from the SigmaHQ repository."""
        if not self.is_repo_cloned():
            return SyncResult(
                success=False,
                message="Repository not cloned",
                error="Must clone repository before pulling",
            )

        try:
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=str(self.base_path),
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                return SyncResult(
                    success=False,
                    message="Pull failed",
                    error=result.stderr,
                )

            commit_hash = self.get_current_commit_hash()
            rule_count = self.count_rules()

            return SyncResult(
                success=True,
                message="Repository updated successfully",
                commit_hash=commit_hash,
                rule_count=rule_count,
            )

        except subprocess.TimeoutExpired:
            return SyncResult(
                success=False,
                message="Pull timed out",
                error="Git pull operation timed out after 2 minutes",
            )
        except Exception as e:
            return SyncResult(
                success=False,
                message="Pull failed",
                error=str(e),
            )

    def get_current_commit_hash(self) -> str | None:
        """Get the current commit hash of the repository."""
        if not self.is_repo_cloned():
            return None

        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.base_path),
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def count_rules(self) -> int:
        """Count the number of YAML rule files in the repository."""
        rules_dir = self.get_rules_directory()
        if not rules_dir.exists():
            return 0
        return sum(1 for _ in rules_dir.rglob("*.yml"))


# Singleton instance
sigmahq_service = SigmaHQService()
