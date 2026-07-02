"""Tests for CHAD_MODE config setting."""

import pytest


class TestChadModeConfig:
    def test_chad_mode_defaults_to_push(self, monkeypatch):
        """Default deployment mode should be 'push'."""
        # Clear any existing CHAD_MODE
        monkeypatch.delenv("CHAD_MODE", raising=False)
        # Force re-import of settings
        import importlib

        from app.core import config
        importlib.reload(config)
        from app.core.config import Settings
        settings = Settings()
        assert settings.CHAD_MODE == "push"

    def test_chad_mode_accepts_pull(self, monkeypatch):
        """Should accept 'pull' for pull-only deployment."""
        monkeypatch.setenv("CHAD_MODE", "pull")
        import importlib

        from app.core import config
        importlib.reload(config)
        from app.core.config import Settings
        settings = Settings()
        assert settings.CHAD_MODE == "pull"

    def test_chad_mode_rejects_invalid(self, monkeypatch):
        """Should reject invalid mode values."""
        from pydantic_core import ValidationError

        from app.core.config import Settings
        # Create a Settings instance with invalid CHAD_MODE directly
        with pytest.raises(ValidationError, match="CHAD_MODE must be 'push' or 'pull'"):
            Settings(CHAD_MODE="invalid")

    def test_is_pull_only_property_push(self, monkeypatch):
        """is_pull_only should return False in push mode."""
        monkeypatch.delenv("CHAD_MODE", raising=False)
        import importlib

        from app.core import config
        importlib.reload(config)
        from app.core.config import Settings
        settings = Settings()
        assert settings.is_pull_only is False

    def test_is_pull_only_property_pull(self, monkeypatch):
        """is_pull_only should return True in pull-only deployment."""
        monkeypatch.setenv("CHAD_MODE", "pull")
        import importlib

        from app.core import config
        importlib.reload(config)
        from app.core.config import Settings
        settings = Settings()
        assert settings.is_pull_only is True


class TestDelegatedAuthConfig:
    def test_delegated_auth_defaults_off(self, monkeypatch):
        """Delegated suite auth must be opt-in: flag off, secret unset."""
        monkeypatch.delenv("CHAD_DELEGATED_AUTH", raising=False)
        monkeypatch.delenv("VF_SESSION_SECRET", raising=False)
        from app.core.config import Settings
        settings = Settings()
        assert settings.CHAD_DELEGATED_AUTH is False
        assert settings.VF_SESSION_SECRET is None

    def test_delegated_auth_env_override(self, monkeypatch):
        """Both fields must be settable from the environment (suite compose sets them)."""
        monkeypatch.setenv("CHAD_DELEGATED_AUTH", "true")
        monkeypatch.setenv("VF_SESSION_SECRET", "shared-nextauth-secret-32-chars-xx")
        from app.core.config import Settings
        settings = Settings()
        assert settings.CHAD_DELEGATED_AUTH is True
        assert settings.VF_SESSION_SECRET == "shared-nextauth-secret-32-chars-xx"
