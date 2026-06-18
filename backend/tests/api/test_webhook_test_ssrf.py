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

        response = await authenticated_client.post(
            f"/api/webhooks/{webhook.id}/test"
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
            f"/api/webhooks/{webhook.id}/test"
        )

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "SSRF" in (body["error"] or "")
