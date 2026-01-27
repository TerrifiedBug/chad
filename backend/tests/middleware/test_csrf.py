"""Tests for CSRF middleware."""

import pytest
from app.core.csrf import is_safe_origin


def test_safe_origin_allows_localhost_in_debug():
    """Test localhost origins are allowed in DEBUG mode."""
    from app.core.config import settings
    original_debug = settings.DEBUG
    settings.DEBUG = True

    try:
        assert is_safe_origin("http://localhost:3000", None, None, None) is True
        assert is_safe_origin(None, "http://localhost:3000", None, None) is True
    finally:
        settings.DEBUG = original_debug


def test_safe_origin_validates_against_app_url():
    """Test origin validation against configured APP_URL."""
    app_url = "https://chad.example.com"

    # Valid origin matching APP_URL
    assert is_safe_origin("https://chad.example.com", None, app_url, None) is True

    # Invalid origin not matching APP_URL
    assert is_safe_origin("https://evil.com", None, app_url, None) is False


def test_safe_origin_validates_referer_as_fallback():
    """Test referer validation when origin is missing."""
    app_url = "https://chad.example.com"

    # Valid referer matching APP_URL
    assert is_safe_origin(None, "https://chad.example.com/alerts", app_url, None) is True

    # Invalid referer not matching APP_URL
    assert is_safe_origin(None, "https://evil.com", app_url, None) is False


def test_safe_origin_rejects_invalid_app_url():
    """Test invalid APP_URL format is handled safely."""
    # Invalid APP_URL (no hostname)
    assert is_safe_origin("https://evil.com", None, "not-a-url", None) is False


def test_safe_origin_validates_host_header():
    """Test host header validation for reverse proxy scenarios."""
    app_url = "https://chad.example.com"

    # Valid host matching APP_URL hostname
    assert is_safe_origin(None, None, app_url, "chad.example.com") is True

    # Invalid host not matching APP_URL hostname
    assert is_safe_origin(None, None, app_url, "evil.com") is False

    # Host with port (common in reverse proxy scenarios)
    assert is_safe_origin(None, None, app_url, "chad.example.com:80") is False


def test_safe_origin_allows_localhost_host_in_debug():
    """Test localhost host header is allowed in DEBUG mode."""
    from app.core.config import settings
    original_debug = settings.DEBUG
    settings.DEBUG = True

    try:
        # Localhost hosts should be allowed in DEBUG mode
        assert is_safe_origin(None, None, None, "localhost") is True
        assert is_safe_origin(None, None, None, "127.0.0.1") is True
        assert is_safe_origin(None, None, None, "frontend") is True

        # But not in production
        settings.DEBUG = False
        assert is_safe_origin(None, None, None, "localhost") is False
    finally:
        settings.DEBUG = original_debug


def test_safe_origin_combines_origin_referer_host():
    """Test that origin, referer, and host are all checked."""
    app_url = "https://chad.example.com"

    # Valid origin, invalid host (origin should pass)
    assert is_safe_origin("https://chad.example.com", None, app_url, "evil.com") is True

    # Invalid origin, valid host (host should pass)
    assert is_safe_origin("https://evil.com", None, app_url, "chad.example.com") is True

    # All invalid (should fail)
    assert is_safe_origin("https://evil.com", None, app_url, "evil.com") is False

    # None of origin/referer/host (should fail)
    assert is_safe_origin(None, None, app_url, None) is False
