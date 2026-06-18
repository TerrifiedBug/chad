"""Tests that the webhook /{id}/test endpoint enforces SSRF protection.

The real send paths already sanitize the destination URL via
``sanitize_webhook_url`` immediately before egress; this pins the same guard on
the admin "Send test" endpoint so it cannot be used to probe link-local /
cloud-metadata addresses (e.g. 169.254.169.254).
"""

import uuid

import pytest
from httpx import AsyncClient

from app.models.notification_settings import Webhook


async def _make_webhook(test_session, url: str) -> Webhook:
    """Persist a webhook row with the given URL and return it."""
    webhook = Webhook(
        id=uuid.uuid4(),
        name=f"ssrf-test-{uuid.uuid4().hex[:8]}",
        url=url,
        header_name=None,
        header_value=None,
        provider="generic",
        enabled=True,
    )
    test_session.add(webhook)
    await test_session.commit()
    await test_session.refresh(webhook)
    return webhook


class TestWebhookTestEndpointSSRF:
    """POST /api/webhooks/{id}/test must block SSRF targets."""

    @pytest.mark.asyncio
    async def test_metadata_ip_is_blocked(
        self, authenticated_client: AsyncClient, test_session, monkeypatch
    ):
        """A webhook pointing at the cloud-metadata IP is rejected, not sent."""
        import app.core.config as config_module

        # Dev/CI may enable the internal-IP escape hatch; force production posture.
        monkeypatch.setattr(
            config_module.settings, "ALLOW_INTERNAL_WEBHOOK_IPS", False
        )

        webhook = await _make_webhook(
            test_session, "http://169.254.169.254/latest/meta-data/"
        )

        # The endpoint takes no request body; the real frontend client still
        # sends an application/json Content-Type on every POST, which the
        # RequestValidationMiddleware requires. Mirror that with json={}.
        response = await authenticated_client.post(
            f"/api/webhooks/{webhook.id}/test", json={}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "SSRF" in (body["error"] or "")

    @pytest.mark.asyncio
    async def test_non_http_scheme_is_blocked(
        self, authenticated_client: AsyncClient, test_session, monkeypatch
    ):
        """Non-http(s) schemes are blocked even when internal IPs are allowed."""
        import app.core.config as config_module

        monkeypatch.setattr(
            config_module.settings, "ALLOW_INTERNAL_WEBHOOK_IPS", True
        )

        webhook = await _make_webhook(test_session, "file:///etc/passwd")

        response = await authenticated_client.post(
            f"/api/webhooks/{webhook.id}/test", json={}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "SSRF" in (body["error"] or "")

    @pytest.mark.asyncio
    async def test_public_url_is_sent_sanitized(
        self, authenticated_client: AsyncClient, test_session, monkeypatch
    ):
        """A public-resolving webhook URL passes the guard and is posted sanitized."""
        import socket

        import app.core.config as config_module

        monkeypatch.setattr(
            config_module.settings, "ALLOW_INTERNAL_WEBHOOK_IPS", False
        )

        # Persist the webhook BEFORE patching DNS: getaddrinfo is shared
        # process-wide, so a blanket override would also break the test DB
        # connection's hostname resolution.
        webhook = await _make_webhook(test_session, "https://example.com/webhook")

        # Resolve only example.com to a fixed public IP (offline, deterministic);
        # defer everything else to the real resolver so DB/other lookups work.
        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, *args, **kwargs):
            if host == "example.com":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
                ]
            return real_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(
            "app.services.webhooks.socket.getaddrinfo", fake_getaddrinfo
        )

        sent = {}

        class _StubResponse:
            is_success = True
            status_code = 200

        # Patching AsyncClient.post is process-wide, so it also intercepts the
        # test client (authenticated_client) that drives the app. Only stub the
        # outbound call to the webhook host; delegate everything else (including
        # the test client's request into the app) to the real implementation.
        import httpx

        real_post = httpx.AsyncClient.post

        async def _fake_post(self, url, *args, **kwargs):
            if "example.com" in str(url):
                sent["url"] = url
                return _StubResponse()
            return await real_post(self, url, *args, **kwargs)

        monkeypatch.setattr("httpx.AsyncClient.post", _fake_post)

        response = await authenticated_client.post(
            f"/api/webhooks/{webhook.id}/test", json={}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["status_code"] == 200
        # The endpoint must post the sanitized URL, not bypass the guard.
        assert sent["url"] == "https://example.com/webhook"
