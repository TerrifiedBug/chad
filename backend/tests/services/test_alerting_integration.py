"""
Integration tests for the full alerting flow.

Tests the complete path from log ingestion through percolation to alert
creation and webhook notification. This is a critical test for verifying
the core detection pipeline works end-to-end.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.alerts import AlertService
from app.services.percolator import PercolatorService
from app.services.webhooks import (
    format_discord_payload,
    format_generic_payload,
    format_slack_payload,
    send_alert_to_webhooks,
    should_send_webhook,
)


class TestFullAlertingFlow:
    """
    Test the complete alerting pipeline:
    1. Deploy rule to percolator index
    2. Match log against percolator
    3. Create alert with full metadata
    4. Send webhook notification
    """

    @pytest.fixture
    def mock_opensearch_client(self):
        """Create a mock OpenSearch client with percolation support."""
        client = MagicMock()

        # Track indexed documents for percolation simulation
        percolator_docs = {}
        alert_docs = {}

        def index_side_effect(index=None, body=None, id=None, **kwargs):
            doc_id = id or str(uuid.uuid4())
            if index and "percolator" in index:
                percolator_docs[doc_id] = body
            else:
                alert_docs[doc_id] = body
            return {"_id": doc_id, "result": "created"}

        def search_side_effect(index=None, body=None, **kwargs):
            # Simulate percolate query
            if body and "percolate" in str(body):
                # Return all deployed rules as matches (simplified)
                hits = []
                for doc_id, doc in percolator_docs.items():
                    if doc.get("enabled", True):
                        hits.append({
                            "_index": index,
                            "_id": doc_id,
                            "_score": 1.0,
                            "_source": doc,
                        })
                return {
                    "hits": {
                        "total": {"value": len(hits)},
                        "hits": hits,
                    }
                }
            return {"hits": {"total": {"value": 0}, "hits": []}}

        def get_side_effect(index=None, id=None, **kwargs):
            if id in percolator_docs:
                return {"_source": percolator_docs[id]}
            raise Exception("Not found")

        # Use side_effect to maintain MagicMock while adding custom behavior
        client.index.side_effect = index_side_effect
        client.search.side_effect = search_side_effect
        client.get.side_effect = get_side_effect
        client.indices.exists.return_value = True
        client.indices.create = MagicMock()

        return client

    def test_full_alerting_pipeline(self, mock_opensearch_client):
        """
        Test complete flow: deploy rule -> match log -> create alert.

        This test verifies that:
        1. Rules are deployed with all metadata (title, severity, tags)
        2. Percolation returns the full rule metadata
        3. Alerts are created with the correct rule information
        """
        # Initialize services
        percolator = PercolatorService(mock_opensearch_client)
        alert_service = AlertService(mock_opensearch_client)

        # Step 1: Deploy a detection rule
        rule_id = str(uuid.uuid4())
        rule_title = "Test System Information Discovery"
        rule_severity = "high"
        rule_tags = ["attack.discovery", "attack.t1082"]

        percolator_index = "chad-percolator-test-logs"
        alerts_index = "chad-alerts-2026.01"

        percolator.deploy_rule(
            percolator_index=percolator_index,
            rule_id=rule_id,
            query={"query_string": {"query": "source_type:EXECVE AND command:uname"}},
            title=rule_title,
            severity=rule_severity,
            tags=rule_tags,
        )

        # Verify rule was indexed with all metadata
        indexed_doc = mock_opensearch_client.index.call_args[1]["body"]
        assert indexed_doc["rule_id"] == rule_id
        assert indexed_doc["rule_title"] == rule_title
        assert indexed_doc["severity"] == rule_severity
        assert indexed_doc["tags"] == rule_tags

        # Step 2: Create a test log that should match
        test_log = {
            "@timestamp": datetime.now(UTC).isoformat(),
            "source_type": "EXECVE",
            "command": "uname",
            "host": {"name": "test-server"},
        }

        # Step 3: Run percolation
        matches = alert_service.match_log(percolator_index, test_log)

        # Verify we got a match with full metadata
        assert len(matches) == 1
        match = matches[0]
        assert match["rule_id"] == rule_id
        assert match["rule_title"] == rule_title
        assert match["severity"] == rule_severity
        assert match["tags"] == rule_tags

        # Step 4: Create alert from match
        alert = alert_service.create_alert(
            alerts_index=alerts_index,
            rule_id=match["rule_id"],
            rule_title=match["rule_title"],
            severity=match["severity"],
            tags=match["tags"],
            log_document=test_log,
        )

        # Verify alert has all expected fields
        assert alert["alert_id"] is not None
        assert alert["rule_id"] == rule_id
        assert alert["rule_title"] == rule_title
        assert alert["severity"] == rule_severity
        assert alert["tags"] == rule_tags
        assert alert["status"] == "new"
        assert alert["log_document"] == test_log
        assert "created_at" in alert
        assert "updated_at" in alert

    @pytest.mark.skip(reason="Enabled/disabled state no longer stored in percolator - managed via deploy/undeploy")
    def test_disabled_rules_not_matched(self, mock_opensearch_client):
        """Verify that disabled rules don't generate alerts.

        Note: This test is skipped because the enabled/disabled state is now managed
        at the database level through deploy/undeploy operations, not as a field in
        the percolator document. A disabled rule is simply not deployed to the percolator.
        """
        pass

    def test_multiple_rules_match(self, mock_opensearch_client):
        """Test that multiple rules can match a single log."""
        percolator = PercolatorService(mock_opensearch_client)
        alert_service = AlertService(mock_opensearch_client)

        percolator_index = "chad-percolator-multi"

        # Deploy multiple rules
        for i in range(3):
            percolator.deploy_rule(
                percolator_index=percolator_index,
                rule_id=f"rule-{i}",
                query={"match_all": {}},
                title=f"Rule {i}",
                severity=["low", "medium", "high"][i],
                tags=[f"tag-{i}"],
            )

        # Match log - should match all rules
        test_log = {"message": "test"}
        matches = alert_service.match_log(percolator_index, test_log)

        assert len(matches) == 3
        severities = [m["severity"] for m in matches]
        assert set(severities) == {"low", "medium", "high"}


class TestWebhookPayloadFormatting:
    """Test webhook payload formatting for different providers."""

    @pytest.fixture
    def sample_alert(self):
        """Create a sample alert for testing."""
        return {
            "alert_id": "test-alert-123",
            "rule_id": "test-rule-456",
            "rule_title": "Suspicious Process Execution",
            "severity": "high",
            "status": "new",
            "tags": ["attack.execution", "attack.t1059"],
            "created_at": "2026-01-22T10:30:00Z",
        }

    def test_generic_payload_format(self, sample_alert):
        """Test generic webhook payload contains required fields."""
        payload = format_generic_payload(sample_alert)

        assert payload["event"] == "alert.created"
        assert "timestamp" in payload
        assert payload["alert"]["alert_id"] == "test-alert-123"
        assert payload["alert"]["rule_title"] == "Suspicious Process Execution"
        assert payload["alert"]["severity"] == "high"
        assert payload["alert"]["status"] == "new"
        assert payload["alert"]["tags"] == ["attack.execution", "attack.t1059"]

    def test_discord_payload_format(self, sample_alert):
        """Test Discord webhook payload has correct embed structure."""
        payload = format_discord_payload(sample_alert)

        assert "embeds" in payload
        assert len(payload["embeds"]) == 1

        embed = payload["embeds"][0]
        assert "Suspicious Process Execution" in embed["title"]
        assert "HIGH" in embed["description"]
        assert embed["color"] == 0xFF8C00  # Orange for high severity
        assert len(embed["fields"]) >= 3
        assert embed["footer"]["text"] == "CHAD Alert System"

    def test_slack_payload_format(self, sample_alert):
        """Test Slack webhook payload has correct block structure."""
        payload = format_slack_payload(sample_alert)

        assert "blocks" in payload
        assert len(payload["blocks"]) >= 2

        # Check header block
        header = payload["blocks"][0]
        assert header["type"] == "header"
        assert "Suspicious Process Execution" in header["text"]["text"]

        # Check section block has fields
        section = payload["blocks"][1]
        assert section["type"] == "section"
        assert "fields" in section

    def test_discord_severity_colors(self):
        """Test Discord embed colors match severity levels."""
        severities = {
            "critical": 0xFF0000,  # Red
            "high": 0xFF8C00,      # Orange
            "medium": 0xFFD700,    # Gold
            "low": 0x4169E1,       # Blue
            "informational": 0x808080,  # Gray
        }

        for severity, expected_color in severities.items():
            alert = {"severity": severity, "rule_title": "Test", "tags": []}
            payload = format_discord_payload(alert)
            assert payload["embeds"][0]["color"] == expected_color


class TestWebhookSeverityFiltering:
    """Test webhook severity filtering logic."""

    def test_all_filter_allows_everything(self):
        """Test that 'all' filter allows all severities."""
        for severity in ["critical", "high", "medium", "low", "informational"]:
            assert should_send_webhook(severity, "all") is True

    def test_critical_only_filter(self):
        """Test critical-only filter."""
        assert should_send_webhook("critical", "critical") is True
        assert should_send_webhook("high", "critical") is False
        assert should_send_webhook("medium", "critical") is False
        assert should_send_webhook("low", "critical") is False
        assert should_send_webhook("informational", "critical") is False

    def test_high_and_above_filter(self):
        """Test high-and-above filter."""
        assert should_send_webhook("critical", "high") is True
        assert should_send_webhook("high", "high") is True
        assert should_send_webhook("medium", "high") is False
        assert should_send_webhook("low", "high") is False

    def test_medium_and_above_filter(self):
        """Test medium-and-above filter."""
        assert should_send_webhook("critical", "medium") is True
        assert should_send_webhook("high", "medium") is True
        assert should_send_webhook("medium", "medium") is True
        assert should_send_webhook("low", "medium") is False

    def test_low_and_above_filter(self):
        """Test low-and-above filter."""
        assert should_send_webhook("critical", "low") is True
        assert should_send_webhook("high", "low") is True
        assert should_send_webhook("medium", "low") is True
        assert should_send_webhook("low", "low") is True
        assert should_send_webhook("informational", "low") is False


class TestWebhookNotificationSending:
    """Test webhook notification sending."""

    @pytest.fixture
    def sample_alert(self):
        return {
            "alert_id": "test-123",
            "rule_id": "rule-456",
            "rule_title": "Test Alert",
            "severity": "high",
            "status": "new",
            "tags": ["test"],
            "created_at": datetime.now(UTC).isoformat(),
        }

    @pytest.mark.asyncio
    async def test_send_alert_to_webhooks_disabled(self, sample_alert):
        """Test that no webhooks are sent when disabled."""
        with patch(
            "app.services.webhooks.get_webhook_config",
            new_callable=AsyncMock,
            return_value={"enabled": False, "webhooks": []},
        ):
            results = await send_alert_to_webhooks(sample_alert)
            assert results == {}

    @pytest.mark.asyncio
    async def test_send_alert_to_webhooks_no_config(self, sample_alert):
        """Test handling of missing webhook config."""
        with patch(
            "app.services.webhooks.get_webhook_config",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await send_alert_to_webhooks(sample_alert)
            assert results == {}

    @pytest.mark.asyncio
    async def test_send_alert_severity_filtering(self, sample_alert):
        """Test that severity filtering works for webhooks."""
        sample_alert["severity"] = "low"

        with patch(
            "app.services.webhooks.get_webhook_config",
            new_callable=AsyncMock,
            return_value={
                "enabled": True,
                "webhooks": [
                    {
                        "name": "Critical Only",
                        "url": "https://example.com/webhook",
                        "provider": "generic",
                        "severity_filter": "critical",
                        "enabled": True,
                    }
                ],
            },
        ), patch(
            "app.services.webhooks.send_webhook",
            new_callable=AsyncMock,
        ) as mock_send:
            results = await send_alert_to_webhooks(sample_alert)
            # Should not send because severity (low) doesn't meet filter (critical)
            mock_send.assert_not_called()
            assert results == {}

    @pytest.mark.asyncio
    async def test_send_alert_to_multiple_webhooks(self, sample_alert):
        """Test sending to multiple webhooks concurrently."""
        with patch(
            "app.services.webhooks.get_webhook_config",
            new_callable=AsyncMock,
            return_value={
                "enabled": True,
                "webhooks": [
                    {
                        "name": "Discord",
                        "url": "https://discord.com/webhook",
                        "provider": "discord",
                        "severity_filter": "all",
                        "enabled": True,
                    },
                    {
                        "name": "Slack",
                        "url": "https://hooks.slack.com/webhook",
                        "provider": "slack",
                        "severity_filter": "all",
                        "enabled": True,
                    },
                ],
            },
        ), patch(
            "app.services.webhooks.send_webhook",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_send:
            results = await send_alert_to_webhooks(sample_alert)

            assert mock_send.call_count == 2
            assert results == {"Discord": True, "Slack": True}
