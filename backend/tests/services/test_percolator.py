"""Tests for the Percolator service."""

from unittest.mock import MagicMock

from app.services.percolator import PERCOLATOR_MAPPING, PercolatorService


class TestPercolatorIndexNaming:
    """Test percolator index name generation."""

    def test_simple_pattern(self):
        """Test simple index pattern conversion."""
        service = PercolatorService(MagicMock())
        assert service.get_percolator_index_name("logs-windows-*") == "chad-percolator-logs-windows"

    def test_wildcard_at_end(self):
        """Test pattern ending with wildcard."""
        service = PercolatorService(MagicMock())
        assert service.get_percolator_index_name("auditbeat-*") == "chad-percolator-auditbeat"

    def test_double_wildcard(self):
        """Test pattern with multiple wildcards."""
        service = PercolatorService(MagicMock())
        assert service.get_percolator_index_name("logs-*-*") == "chad-percolator-logs"

    def test_no_wildcard(self):
        """Test pattern without wildcard."""
        service = PercolatorService(MagicMock())
        assert service.get_percolator_index_name("specific-index") == "chad-percolator-specific-index"


class TestPercolatorServiceMocked:
    """Test percolator service with mocked OpenSearch client."""

    def test_ensure_percolator_index_creates_when_missing(self):
        """Test that index is created when it doesn't exist."""
        mock_client = MagicMock()
        mock_client.indices.exists.return_value = False
        service = PercolatorService(mock_client)

        service.ensure_percolator_index("percolator-test")

        mock_client.indices.exists.assert_called_once_with(index="percolator-test")
        mock_client.indices.create.assert_called_once_with(
            index="percolator-test",
            body=PERCOLATOR_MAPPING,
        )

    def test_ensure_percolator_index_skips_when_exists(self):
        """Test that index creation is skipped when it exists."""
        mock_client = MagicMock()
        mock_client.indices.exists.return_value = True
        service = PercolatorService(mock_client)

        service.ensure_percolator_index("percolator-test")

        mock_client.indices.exists.assert_called_once_with(index="percolator-test")
        mock_client.indices.create.assert_not_called()

    def test_deploy_rule(self):
        """Test rule deployment."""
        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("not found")  # Rule doesn't exist yet
        service = PercolatorService(mock_client)

        service.deploy_rule(
            percolator_index="percolator-test",
            rule_id="test-rule-123",
            query={"query": {"match": {"message": "error"}}},
            title="Test Rule",
            severity="high",
            tags=["attack.discovery"],
        )

        mock_client.index.assert_called_once()
        call_kwargs = mock_client.index.call_args[1]
        assert call_kwargs["index"] == "percolator-test"
        assert call_kwargs["id"] == "test-rule-123"
        assert call_kwargs["refresh"] is True
        assert call_kwargs["body"]["rule_id"] == "test-rule-123"
        assert call_kwargs["body"]["rule_title"] == "Test Rule"
        assert call_kwargs["body"]["severity"] == "high"
        assert call_kwargs["body"]["tags"] == ["attack.discovery"]

    def test_undeploy_rule_success(self):
        """Test successful rule undeployment."""
        mock_client = MagicMock()
        mock_client.delete.return_value = {"result": "deleted"}
        service = PercolatorService(mock_client)

        result = service.undeploy_rule("percolator-test", "test-rule-123")

        assert result is True
        mock_client.delete.assert_called_once_with(
            index="percolator-test",
            id="test-rule-123",
            refresh=True,
        )

    def test_undeploy_rule_not_found(self):
        """Test undeploying a rule that doesn't exist."""
        mock_client = MagicMock()
        mock_client.delete.side_effect = Exception("not found")
        service = PercolatorService(mock_client)

        result = service.undeploy_rule("percolator-test", "test-rule-123")

        assert result is False

    def test_update_rule_status(self):
        """Test updating rule enabled status."""
        mock_client = MagicMock()
        service = PercolatorService(mock_client)

        result = service.update_rule_status("percolator-test", "test-rule-123", enabled=False)

        assert result is True
        mock_client.update.assert_called_once()
        call_kwargs = mock_client.update.call_args[1]
        assert call_kwargs["index"] == "percolator-test"
        assert call_kwargs["id"] == "test-rule-123"
        assert call_kwargs["body"]["doc"]["enabled"] is False
        assert "updated_at" in call_kwargs["body"]["doc"]

    def test_get_deployed_rule_found(self):
        """Test getting a deployed rule that exists."""
        mock_client = MagicMock()
        mock_client.get.return_value = {
            "_source": {
                "rule_id": "test-rule-123",
                "rule_title": "Test Rule",
                "enabled": True,
            }
        }
        service = PercolatorService(mock_client)

        result = service.get_deployed_rule("percolator-test", "test-rule-123")

        assert result is not None
        assert result["rule_id"] == "test-rule-123"
        assert result["enabled"] is True

    def test_get_deployed_rule_not_found(self):
        """Test getting a deployed rule that doesn't exist."""
        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("not found")
        service = PercolatorService(mock_client)

        result = service.get_deployed_rule("percolator-test", "test-rule-123")

        assert result is None

    def test_is_rule_deployed_true(self):
        """Test checking if rule is deployed when it is."""
        mock_client = MagicMock()
        mock_client.exists.return_value = True
        service = PercolatorService(mock_client)

        result = service.is_rule_deployed("percolator-test", "test-rule-123")

        assert result is True

    def test_is_rule_deployed_false(self):
        """Test checking if rule is deployed when it isn't."""
        mock_client = MagicMock()
        mock_client.exists.return_value = False
        service = PercolatorService(mock_client)

        result = service.is_rule_deployed("percolator-test", "test-rule-123")

        assert result is False
