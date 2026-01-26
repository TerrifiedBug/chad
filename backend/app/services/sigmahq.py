"""
SigmaHQ integration service for managing the SigmaHQ rule repository.

Handles git operations (clone, pull) and file system access to rules.
"""
import logging
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

import yaml


logger = logging.getLogger(__name__)


class RuleType(str, Enum):
    DETECTION = "detection"
    THREAT_HUNTING = "threat_hunting"
    EMERGING_THREATS = "emerging_threats"


RULE_DIRECTORIES = {
    RuleType.DETECTION: "rules",
    RuleType.THREAT_HUNTING: "rules-threat-hunting",
    RuleType.EMERGING_THREATS: "rules-emerging-threats",
}


@dataclass
class SyncResult:
    success: bool
    message: str
    commit_hash: str | None = None
    rule_counts: dict[str, int] | None = None
    error: str | None = None


class SigmaHQService:
    DEFAULT_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
    DEFAULT_BASE_PATH = Path("/data/sigmahq")

    # Allowed git repositories (whitelist)
    ALLOWED_GIT_HOSTS = [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ]

    def __init__(self, base_path: Path | None = None):
        self.base_path = base_path or self.DEFAULT_BASE_PATH

    @staticmethod
    def validate_git_url(url: str) -> tuple[bool, str | None]:
        """
        Validate that a git URL is safe to use.

        Args:
            url: The git repository URL to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url or not url.strip():
            return False, "URL cannot be empty"

        try:
            parsed = urlparse(url.strip())

            # Must be https or git protocol for security
            if parsed.scheme not in ["https", "git"]:
                return False, "Only HTTPS and Git protocol URLs are allowed"

            # Must have a hostname
            if not parsed.hostname:
                return False, "Invalid URL format"

            # Check hostname against whitelist
            if parsed.hostname not in SigmaHQService.ALLOWED_GIT_HOSTS:
                return False, f"Repository host '{parsed.hostname}' is not allowed. Allowed hosts: {', '.join(SigmaHQService.ALLOWED_GIT_HOSTS)}"

            # Prevent file system traversal attempts in path
            if "../" in url or url.startswith("/") or url.startswith("~"):
                return False, "Invalid URL format: path traversal detected"

            # Basic format check for git URLs
            if parsed.scheme == "git" and "//" not in url:
                return False, "Invalid git URL format"

            logger.info(f"Git URL validation passed: {url[:50]}...")

            return True, None

        except Exception as e:
            logger.error(f"Error validating git URL: {e}")
            return False, f"URL validation failed: {str(e)}"

    def get_rules_directory(self, rule_type: RuleType = RuleType.DETECTION) -> Path:
        """Get the path to a rules directory by type."""
        return self.base_path / RULE_DIRECTORIES[rule_type]

    def is_repo_cloned(self) -> bool:
        """Check if the SigmaHQ repository is already cloned."""
        git_dir = self.base_path / ".git"
        rules_dir = self.get_rules_directory(RuleType.DETECTION)
        return git_dir.exists() and rules_dir.exists()

    def clone_repo(self, repo_url: str | None = None) -> SyncResult:
        """Clone the SigmaHQ repository."""
        url = repo_url or self.DEFAULT_REPO_URL

        # Validate URL before executing git command
        is_valid, error_msg = self.validate_git_url(url)
        if not is_valid:
            logger.warning(f"CSRF/Security: Invalid git URL blocked: {url} - {error_msg}")
            return SyncResult(
                success=False,
                message="Invalid repository URL",
                error=error_msg,
            )

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
            rule_counts = self.count_rules_all()

            return SyncResult(
                success=True,
                message="Repository cloned successfully",
                commit_hash=commit_hash,
                rule_counts=rule_counts,
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
            rule_counts = self.count_rules_all()

            return SyncResult(
                success=True,
                message="Repository updated successfully",
                commit_hash=commit_hash,
                rule_counts=rule_counts,
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

    def count_rules(self, rule_type: RuleType = RuleType.DETECTION) -> int:
        """Count the number of YAML rule files in a specific directory."""
        rules_dir = self.get_rules_directory(rule_type)
        if not rules_dir.exists():
            return 0
        return sum(1 for _ in rules_dir.rglob("*.yml"))

    def count_rules_all(self) -> dict[str, int]:
        """Count rules in each directory."""
        counts = {}
        for rule_type in RuleType:
            rules_dir = self.get_rules_directory(rule_type)
            if rules_dir.exists():
                counts[rule_type.value] = sum(1 for _ in rules_dir.rglob("*.yml"))
            else:
                counts[rule_type.value] = 0
        return counts

    def get_category_tree(self, rule_type: RuleType = RuleType.DETECTION) -> dict:
        """
        Build a nested category tree from the rules directory structure.

        Args:
            rule_type: The type of rules directory to browse.

        Returns:
            {
                "windows": {
                    "count": 150,
                    "children": {
                        "process_creation": {"count": 50, "children": {}},
                        "registry": {"count": 30, "children": {}},
                    }
                },
                "linux": {...}
            }
        """
        rules_dir = self.get_rules_directory(rule_type)
        if not rules_dir.exists():
            return {}

        def build_tree(path: Path, relative_to: Path) -> dict:
            tree = {}
            for item in sorted(path.iterdir()):
                if item.is_dir() and not item.name.startswith("."):
                    subtree = build_tree(item, relative_to)
                    rule_count = sum(1 for _ in item.rglob("*.yml"))
                    tree[item.name] = {
                        "count": rule_count,
                        "children": subtree,
                    }
            return tree

        return build_tree(rules_dir, rules_dir)

    def list_rules_in_category(
        self,
        category_path: str,
        rule_type: RuleType = RuleType.DETECTION,
    ) -> list[dict]:
        """
        List all rules in a specific category directory.

        Args:
            category_path: Relative path like "windows/process_creation"
            rule_type: The type of rules directory to browse.

        Returns:
            List of rule metadata dicts with title, severity, status, path, tags
        """
        rules_dir = self.get_rules_directory(rule_type)
        target_dir = rules_dir / category_path

        # Security: ensure path doesn't escape rules directory
        try:
            target_dir.resolve().relative_to(rules_dir.resolve())
        except ValueError:
            return []

        if not target_dir.exists() or not target_dir.is_dir():
            return []

        rules = []
        for rule_file in sorted(target_dir.glob("*.yml")):
            try:
                content = rule_file.read_text(encoding="utf-8")
                parsed = yaml.safe_load(content)
                if parsed and isinstance(parsed, dict):
                    relative_path = rule_file.relative_to(rules_dir)
                    rules.append({
                        "title": parsed.get("title", rule_file.stem),
                        "status": parsed.get("status", "unknown"),
                        "severity": parsed.get("level", "unknown"),
                        "description": parsed.get("description", ""),
                        "tags": parsed.get("tags", []),
                        "path": str(relative_path),
                        "filename": rule_file.name,
                    })
            except Exception:
                # Skip files that can't be parsed
                continue

        return rules

    def get_rule_content(
        self,
        rule_path: str,
        rule_type: RuleType = RuleType.DETECTION,
    ) -> str | None:
        """
        Get the raw YAML content of a specific rule.

        Args:
            rule_path: Relative path like "windows/process_creation/test_rule.yml"
            rule_type: The type of rules directory to browse.

        Returns:
            Raw YAML content as string, or None if not found
        """
        rules_dir = self.get_rules_directory(rule_type)
        full_path = rules_dir / rule_path

        # Security: ensure path doesn't escape rules directory
        try:
            full_path.resolve().relative_to(rules_dir.resolve())
        except ValueError:
            return None

        if not full_path.exists() or not full_path.is_file():
            return None

        return full_path.read_text(encoding="utf-8")

    def search_rules(
        self,
        query: str,
        limit: int = 100,
        rule_type: RuleType = RuleType.DETECTION,
    ) -> list[dict]:
        """
        Search rules by keyword in title, description, and tags.

        Args:
            query: Search string (case-insensitive)
            limit: Maximum number of results
            rule_type: The type of rules directory to search.

        Returns:
            List of matching rule metadata dicts
        """
        rules_dir = self.get_rules_directory(rule_type)
        if not rules_dir.exists():
            return []

        query_lower = query.lower()
        matches = []

        for rule_file in rules_dir.rglob("*.yml"):
            if len(matches) >= limit:
                break

            try:
                content = rule_file.read_text(encoding="utf-8")
                parsed = yaml.safe_load(content)

                if not parsed or not isinstance(parsed, dict):
                    continue

                # Search in title, description, and tags
                title = str(parsed.get("title", "")).lower()
                description = str(parsed.get("description", "")).lower()
                tags = [str(t).lower() for t in parsed.get("tags", [])]

                if (
                    query_lower in title
                    or query_lower in description
                    or any(query_lower in tag for tag in tags)
                ):
                    relative_path = rule_file.relative_to(rules_dir)
                    matches.append({
                        "title": parsed.get("title", rule_file.stem),
                        "status": parsed.get("status", "unknown"),
                        "severity": parsed.get("level", "unknown"),
                        "description": parsed.get("description", ""),
                        "tags": parsed.get("tags", []),
                        "path": str(relative_path),
                        "filename": rule_file.name,
                    })
            except Exception:
                continue

        return matches


# Singleton instance
sigmahq_service = SigmaHQService()
