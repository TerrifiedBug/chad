"""Tests for mode API endpoint."""

import pytest
from unittest.mock import patch, MagicMock


class TestModeEndpoint:
    @pytest.mark.asyncio
    async def test_get_mode_full_deployment(self, client):
        """Should return full deployment info by default."""
        with patch("app.api.mode.get_settings") as mock_settings:
            mock_settings.return_value.CHAD_MODE = "push"
            mock_settings.return_value.is_pull_only = False

            response = await client.get("/api/mode")

            assert response.status_code == 200
            data = response.json()
            assert data["mode"] == "push"
            assert data["is_pull_only"] is False
            assert data["supports_push"] is True
            assert data["supports_pull"] is True

    @pytest.mark.asyncio
    async def test_get_mode_pull_only_deployment(self, client):
        """Should return pull-only deployment info when configured."""
        with patch("app.api.mode.get_settings") as mock_settings:
            mock_settings.return_value.CHAD_MODE = "pull"
            mock_settings.return_value.is_pull_only = True

            response = await client.get("/api/mode")

            assert response.status_code == 200
            data = response.json()
            assert data["mode"] == "pull"
            assert data["is_pull_only"] is True
            assert data["supports_push"] is False
            assert data["supports_pull"] is True
