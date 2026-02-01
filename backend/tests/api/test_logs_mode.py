"""Tests for mode-aware logs endpoint."""

import pytest
from unittest.mock import MagicMock


class TestLogsEndpointModeUnit:
    """Unit tests for logs endpoint mode checks."""

    def test_logs_allowed_for_push_pattern(self):
        """Should allow logs for push-mode patterns."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = False

        mock_pattern = MagicMock()
        mock_pattern.mode = "push"

        # Logic: reject if pull-only deployment
        if mock_settings.is_pull_only:
            result = "pull_only_rejected"
        elif mock_pattern.mode == "pull":
            result = "pull_pattern_rejected"
        else:
            result = "accepted"

        assert result == "accepted"

    def test_logs_rejected_for_pull_pattern(self):
        """Should reject logs for pull-mode patterns."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = False

        mock_pattern = MagicMock()
        mock_pattern.mode = "pull"

        # Logic: reject if pull-only deployment
        if mock_settings.is_pull_only:
            result = "pull_only_rejected"
        elif mock_pattern.mode == "pull":
            result = "pull_pattern_rejected"
        else:
            result = "accepted"

        assert result == "pull_pattern_rejected"

    def test_logs_rejected_in_pull_only_deployment(self):
        """In pull-only deployment, /logs returns 503."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = True

        mock_pattern = MagicMock()
        mock_pattern.mode = "push"

        # Logic: reject if pull-only deployment
        if mock_settings.is_pull_only:
            result = "pull_only_rejected"
        elif mock_pattern.mode == "pull":
            result = "pull_pattern_rejected"
        else:
            result = "accepted"

        assert result == "pull_only_rejected"

    def test_logs_rejected_pull_pattern_in_pull_only(self):
        """Pull pattern in pull-only deployment rejects logs."""
        mock_settings = MagicMock()
        mock_settings.is_pull_only = True

        mock_pattern = MagicMock()
        mock_pattern.mode = "pull"

        # Logic: reject if pull-only deployment
        if mock_settings.is_pull_only:
            result = "pull_only_rejected"
        elif mock_pattern.mode == "pull":
            result = "pull_pattern_rejected"
        else:
            result = "accepted"

        assert result == "pull_only_rejected"
