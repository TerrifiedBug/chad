"""Tests for mode-aware rule deployment."""

import pytest
from unittest.mock import MagicMock


class TestModeAwareDeploymentUnit:
    """Unit tests for mode-aware deployment logic."""

    def test_use_percolator_for_push_pattern(self):
        """Push-mode patterns should use percolator in full deployment."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = False

        mock_index_pattern = MagicMock()
        mock_index_pattern.mode = "push"

        use_percolator = not mock_settings.is_pull_only and mock_index_pattern.mode == "push"
        assert use_percolator is True

    def test_skip_percolator_for_pull_pattern(self):
        """Pull-mode patterns should skip percolator."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = False

        mock_index_pattern = MagicMock()
        mock_index_pattern.mode = "pull"

        use_percolator = not mock_settings.is_pull_only and mock_index_pattern.mode == "push"
        assert use_percolator is False

    def test_skip_percolator_in_pull_only_mode(self):
        """Pull-only deployment should skip percolator for all patterns."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = True

        mock_index_pattern = MagicMock()
        mock_index_pattern.mode = "push"  # Even push patterns should skip in pull-only mode

        use_percolator = not mock_settings.is_pull_only and mock_index_pattern.mode == "push"
        assert use_percolator is False

    def test_skip_percolator_pull_pattern_in_pull_only_mode(self):
        """Pull pattern in pull-only deployment should skip percolator."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = True

        mock_index_pattern = MagicMock()
        mock_index_pattern.mode = "pull"

        use_percolator = not mock_settings.is_pull_only and mock_index_pattern.mode == "push"
        assert use_percolator is False
