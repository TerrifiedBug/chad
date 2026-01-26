"""Tests for CSRF middleware."""

import pytest
from app.core.csrf import is_safe_origin


def test_safe_origin_allows_localhost_in_debug():
    """Test localhost origins are allowed in DEBUG mode."""
    from app.core.config import settings
    original_debug = settings.DEBUG
    settings.DEBUG = True

    try:
        assert is_safe_origin("http://localhost:3000", None, None) is True
        assert is_safe_origin(None, "http://localhost:3000", None) is True
    finally:
        settings.DEBUG = original_debug


def test_safe_origin_validates_against_app_url():
    """Test origin validation against configured APP_URL."""
    app_url = "https://chad.terrifiedbug.com"

    # Valid origin matching APP_URL
    assert is_safe_origin("https://chad.terrifiedbug.com", None, app_url) is True

    # Invalid origin not matching APP_URL
    assert is_safe_origin("https://evil.com", None, app_url) is False


def test_safe_origin_validates_referer_as_fallback():
    """Test referer validation when origin is missing."""
    app_url = "https://chad.terrifiedbug.com"

    # Valid referer matching APP_URL
    assert is_safe_origin(None, "https://chad.terrifiedbug.com/alerts", app_url) is True

    # Invalid referer not matching APP_URL
    assert is_safe_origin(None, "https://evil.com", app_url) is False


def test_safe_origin_rejects_invalid_app_url():
    """Test invalid APP_URL format is handled safely."""
    # Invalid APP_URL (no hostname)
    assert is_safe_origin("https://evil.com", None, "not-a-url") is False
