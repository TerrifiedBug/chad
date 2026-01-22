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
