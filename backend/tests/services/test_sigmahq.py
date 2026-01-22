# backend/tests/services/test_sigmahq.py
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.sigmahq import SigmaHQService


class TestSigmaHQService:
    def test_get_rules_directory_returns_data_path(self):
        service = SigmaHQService()
        assert service.get_rules_directory() == Path("/data/sigmahq/rules")

    def test_is_repo_cloned_returns_false_when_not_cloned(self, tmp_path):
        service = SigmaHQService(base_path=tmp_path)
        assert service.is_repo_cloned() is False

    def test_is_repo_cloned_returns_true_when_git_exists(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / "rules").mkdir()
        service = SigmaHQService(base_path=tmp_path)
        assert service.is_repo_cloned() is True

    @patch("app.services.sigmahq.subprocess.run")
    def test_clone_repo_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        service = SigmaHQService(base_path=tmp_path)
        result = service.clone_repo("https://github.com/SigmaHQ/sigma.git")
        assert result.success is True
        mock_run.assert_called_once()

    @patch("app.services.sigmahq.subprocess.run")
    def test_pull_repo_success(self, mock_run, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / "rules").mkdir()
        mock_run.return_value = MagicMock(returncode=0, stdout="Already up to date.")
        service = SigmaHQService(base_path=tmp_path)
        result = service.pull_repo()
        assert result.success is True

    @patch("app.services.sigmahq.subprocess.run")
    def test_get_current_commit_hash(self, mock_run, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / "rules").mkdir()
        mock_run.return_value = MagicMock(returncode=0, stdout="abc123\n")
        service = SigmaHQService(base_path=tmp_path)
        assert service.get_current_commit_hash() == "abc123"


class TestSigmaHQRuleBrowsing:
    def test_get_category_tree_returns_nested_structure(self, tmp_path):
        # Create test directory structure
        (tmp_path / "rules" / "windows" / "process_creation").mkdir(parents=True)
        (tmp_path / "rules" / "windows" / "registry").mkdir(parents=True)
        (tmp_path / "rules" / "linux" / "auditd").mkdir(parents=True)

        # Create test rule files
        (tmp_path / "rules" / "windows" / "process_creation" / "proc_creation_win_susp.yml").write_text("title: Test")
        (tmp_path / "rules" / "windows" / "registry" / "registry_add.yml").write_text("title: Test")
        (tmp_path / "rules" / "linux" / "auditd" / "audit_exec.yml").write_text("title: Test")

        service = SigmaHQService(base_path=tmp_path)
        tree = service.get_category_tree()

        assert "windows" in tree
        assert tree["windows"]["count"] == 2
        assert "process_creation" in tree["windows"]["children"]
        assert tree["windows"]["children"]["process_creation"]["count"] == 1

    def test_get_category_tree_returns_empty_when_no_rules_dir(self, tmp_path):
        service = SigmaHQService(base_path=tmp_path)
        tree = service.get_category_tree()
        assert tree == {}

    def test_get_category_tree_ignores_hidden_directories(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        (tmp_path / "rules" / ".git").mkdir(parents=True)
        (tmp_path / "rules" / "windows" / "test.yml").write_text("title: Test")
        (tmp_path / "rules" / ".git" / "hidden.yml").write_text("title: Hidden")

        service = SigmaHQService(base_path=tmp_path)
        tree = service.get_category_tree()

        assert "windows" in tree
        assert ".git" not in tree

    def test_list_rules_in_category(self, tmp_path):
        (tmp_path / "rules" / "windows" / "process_creation").mkdir(parents=True)
        rule_path = tmp_path / "rules" / "windows" / "process_creation" / "test_rule.yml"
        rule_path.write_text("""title: Test Rule
status: experimental
level: high
description: Test description
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'suspicious'
  condition: selection
""")

        service = SigmaHQService(base_path=tmp_path)
        rules = service.list_rules_in_category("windows/process_creation")

        assert len(rules) == 1
        assert rules[0]["title"] == "Test Rule"
        assert rules[0]["severity"] == "high"
        assert rules[0]["path"] == "windows/process_creation/test_rule.yml"

    def test_list_rules_in_category_returns_empty_for_nonexistent(self, tmp_path):
        (tmp_path / "rules").mkdir(parents=True)
        service = SigmaHQService(base_path=tmp_path)
        rules = service.list_rules_in_category("nonexistent/path")
        assert rules == []

    def test_list_rules_in_category_prevents_path_traversal(self, tmp_path):
        (tmp_path / "rules").mkdir(parents=True)
        (tmp_path / "secret").mkdir(parents=True)
        (tmp_path / "secret" / "data.yml").write_text("title: Secret")

        service = SigmaHQService(base_path=tmp_path)
        rules = service.list_rules_in_category("../secret")
        assert rules == []

    def test_list_rules_in_category_handles_invalid_yaml(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        # Valid rule
        (tmp_path / "rules" / "windows" / "valid.yml").write_text("title: Valid Rule\nlevel: high\n")
        # Invalid YAML
        (tmp_path / "rules" / "windows" / "invalid.yml").write_text("title: [invalid yaml\n")

        service = SigmaHQService(base_path=tmp_path)
        rules = service.list_rules_in_category("windows")

        # Should return only the valid rule, skipping the invalid one
        assert len(rules) == 1
        assert rules[0]["title"] == "Valid Rule"

    def test_get_rule_content(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        rule_content = """title: Suspicious Command
status: test
level: medium
"""
        (tmp_path / "rules" / "windows" / "test.yml").write_text(rule_content)

        service = SigmaHQService(base_path=tmp_path)
        content = service.get_rule_content("windows/test.yml")

        assert content == rule_content

    def test_get_rule_content_returns_none_for_nonexistent(self, tmp_path):
        (tmp_path / "rules").mkdir(parents=True)
        service = SigmaHQService(base_path=tmp_path)
        content = service.get_rule_content("nonexistent/rule.yml")
        assert content is None

    def test_get_rule_content_prevents_path_traversal(self, tmp_path):
        (tmp_path / "rules").mkdir(parents=True)
        (tmp_path / "secret.txt").write_text("secret data")

        service = SigmaHQService(base_path=tmp_path)
        content = service.get_rule_content("../secret.txt")
        assert content is None

    def test_search_rules_finds_by_title(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        (tmp_path / "rules" / "windows" / "mimikatz.yml").write_text("""title: Mimikatz Detection
level: high
description: Detects mimikatz usage
tags:
  - attack.credential_access
""")
        (tmp_path / "rules" / "windows" / "other.yml").write_text("""title: Other Rule
level: low
description: Some other detection
""")

        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("mimikatz")

        assert len(results) == 1
        assert results[0]["title"] == "Mimikatz Detection"

    def test_search_rules_finds_by_description(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        (tmp_path / "rules" / "windows" / "test.yml").write_text("""title: Generic Rule
level: medium
description: Detects powershell execution
""")

        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("powershell")

        assert len(results) == 1
        assert results[0]["title"] == "Generic Rule"

    def test_search_rules_finds_by_tag(self, tmp_path):
        (tmp_path / "rules" / "linux").mkdir(parents=True)
        (tmp_path / "rules" / "linux" / "test.yml").write_text("""title: Execution Rule
level: medium
description: Test
tags:
  - attack.execution
  - attack.t1059
""")

        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("t1059")

        assert len(results) == 1
        assert results[0]["title"] == "Execution Rule"

    def test_search_rules_is_case_insensitive(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        (tmp_path / "rules" / "windows" / "test.yml").write_text("""title: MIMIKATZ Detection
level: high
""")

        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("mimikatz")

        assert len(results) == 1

    def test_search_rules_respects_limit(self, tmp_path):
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        for i in range(10):
            (tmp_path / "rules" / "windows" / f"test{i}.yml").write_text(f"""title: Test Rule {i}
level: medium
""")

        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("Test", limit=5)

        assert len(results) == 5

    def test_search_rules_returns_empty_when_no_rules_dir(self, tmp_path):
        service = SigmaHQService(base_path=tmp_path)
        results = service.search_rules("anything")
        assert results == []
