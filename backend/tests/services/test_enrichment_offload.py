"""Tests for deferred (off-hot-path) enrichment: TI/webhook offload + merge."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.alerts import AlertService


class TestMergeAlertEnrichment:
    def test_merge_issues_partial_update(self):
        client = MagicMock()
        AlertService(client).merge_alert_enrichment(
            "chad-alerts-x", "abc123", {"ti_enrichment": {"indicators": [1]}}
        )
        client.update.assert_called_once()
        _, kwargs = client.update.call_args
        assert kwargs["id"] == "abc123"
        assert kwargs["body"] == {
            "doc": {"log_document": {"ti_enrichment": {"indicators": [1]}}}
        }

    def test_merge_noop_on_empty(self):
        client = MagicMock()
        AlertService(client).merge_alert_enrichment("idx", "id", {})
        client.update.assert_not_called()

    def test_merge_swallows_errors(self):
        client = MagicMock()
        client.update.side_effect = Exception("os down")
        # Best-effort: must not raise into the caller.
        AlertService(client).merge_alert_enrichment("idx", "id", {"enrichment": {"a": 1}})


class TestComputeAsyncEnrichment:
    @pytest.mark.asyncio
    async def test_returns_only_ti_and_webhook_keys(self):
        from app.services import enrichment

        async def fake_ti(db, extra, log, ip):
            extra["ti_enrichment"] = {"indicators": ["x"]}

        async def fake_wh(db, extra, log, ip, alert_id, rule_id, rule_title, severity, is_ioc_alert=False):
            extra["enrichment"] = {"field": "v"}

        with (
            patch.object(enrichment, "_enrich_ti", side_effect=fake_ti),
            patch.object(enrichment, "_enrich_webhooks", side_effect=fake_wh),
        ):
            result = await enrichment.compute_async_enrichment(
                AsyncMock(), {"source": {"ip": "1.2.3.4"}}, SimpleNamespace(),
                alert_id="a", rule_id="r", rule_title="t", severity="high",
            )

        assert result == {"ti_enrichment": {"indicators": ["x"]}, "enrichment": {"field": "v"}}

    @pytest.mark.asyncio
    async def test_skips_ti_for_ioc_alert(self):
        from app.services import enrichment

        ti = AsyncMock()

        async def fake_wh(db, extra, log, ip, alert_id, rule_id, rule_title, severity, is_ioc_alert=False):
            extra["enrichment"] = {"k": 1}

        with (
            patch.object(enrichment, "_enrich_ti", ti),
            patch.object(enrichment, "_enrich_webhooks", side_effect=fake_wh),
        ):
            result = await enrichment.compute_async_enrichment(
                AsyncMock(), {}, SimpleNamespace(), is_ioc_alert=True,
            )

        ti.assert_not_called()
        assert result == {"enrichment": {"k": 1}}
