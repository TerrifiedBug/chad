"""Regression tests for webhook SSRF validation (is_safe_url / sanitize_webhook_url).

These tests pin the fail-closed DNS behavior introduced in plan 006: when the
hostname cannot be resolved, validation must REJECT the URL rather than allow it.

``socket.getaddrinfo`` is patched where it is used (the ``socket`` module imported
by ``app.services.webhooks``) so DNS resolution is deterministic and offline.
"""

import socket
from contextlib import ExitStack
from unittest.mock import patch

from app.core.config import settings
from app.services.webhooks import is_safe_url, sanitize_webhook_url


def _addr_info(ip: str):
    """Build a getaddrinfo-style result list for a single IPv4 address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


def _validator_env(*, getaddrinfo_return=None, getaddrinfo_side_effect=None):
    """Patch the validator's DNS lookup and force the internal-IP escape hatch off.

    The dev/CI container may set ``ALLOW_INTERNAL_WEBHOOK_IPS=true`` (an
    intentional escape hatch) which short-circuits the IP-resolution block.
    These tests assert the resolution/blocking path itself, so we pin the flag
    to ``False`` to exercise it deterministically regardless of ambient env.
    """
    stack = ExitStack()
    stack.enter_context(patch.object(settings, "ALLOW_INTERNAL_WEBHOOK_IPS", False))
    kwargs = {}
    if getaddrinfo_return is not None:
        kwargs["return_value"] = getaddrinfo_return
    if getaddrinfo_side_effect is not None:
        kwargs["side_effect"] = getaddrinfo_side_effect
    stack.enter_context(patch("app.services.webhooks.socket.getaddrinfo", **kwargs))
    return stack


class TestIsSafeUrl:
    """SSRF validation behavior for is_safe_url."""

    def test_public_ip_is_allowed(self):
        """A hostname resolving to a public IP is allowed."""
        with _validator_env(getaddrinfo_return=_addr_info("93.184.216.34")):
            is_safe, error = is_safe_url("https://example.com/webhook")
        assert is_safe is True
        assert error == ""

    def test_private_ip_is_blocked(self):
        """A hostname resolving to an RFC1918 private IP is blocked."""
        with _validator_env(getaddrinfo_return=_addr_info("10.0.0.5")):
            is_safe, error = is_safe_url("https://internal.example.com/webhook")
        assert is_safe is False
        assert error

    def test_link_local_metadata_ip_is_blocked(self):
        """A hostname resolving to the link-local cloud-metadata IP is blocked."""
        with _validator_env(getaddrinfo_return=_addr_info("169.254.169.254")):
            is_safe, error = is_safe_url("http://metadata.example.com/latest/meta-data")
        assert is_safe is False
        assert error

    def test_dns_failure_is_blocked(self):
        """Fail-closed: an unresolvable host is rejected (regression for plan 006).

        Before this fix the gaierror branch fell through and ALLOWED the request.
        """
        with _validator_env(
            getaddrinfo_side_effect=socket.gaierror("Name or service not known")
        ):
            is_safe, error = is_safe_url("https://does-not-resolve.invalid/webhook")
        assert is_safe is False
        assert error

    def test_non_http_scheme_is_blocked(self):
        """A non-http(s) scheme (file://) is rejected before any DNS lookup."""
        is_safe, error = is_safe_url("file:///etc/passwd")
        assert is_safe is False
        assert error


class TestSanitizeWebhookUrl:
    """sanitize_webhook_url mirrors the validator and returns None on rejection."""

    def test_public_ip_sanitizes(self):
        """A public-resolving URL passes and is returned sanitized."""
        with _validator_env(getaddrinfo_return=_addr_info("93.184.216.34")):
            sanitized, error = sanitize_webhook_url("https://example.com/webhook")
        assert sanitized == "https://example.com/webhook"
        assert error == ""

    def test_dns_failure_returns_none(self):
        """Fail-closed: an unresolvable host yields (None, error)."""
        with _validator_env(
            getaddrinfo_side_effect=socket.gaierror("Name or service not known")
        ):
            sanitized, error = sanitize_webhook_url("https://does-not-resolve.invalid/webhook")
        assert sanitized is None
        assert error
