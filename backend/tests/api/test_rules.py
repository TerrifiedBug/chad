"""Tests for the rules API endpoints."""

import pytest
from httpx import AsyncClient


class TestRuleValidation:
    """Tests for POST /rules/validate endpoint."""

    @pytest.mark.asyncio
    async def test_validate_requires_auth(self, client: AsyncClient):
        """Validate endpoint requires authentication."""
        response = await client.post(
            "/api/rules/validate",
            json={"yaml_content": "title: Test"},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403


class TestRuleTesting:
    """Tests for POST /rules/test endpoint.

    Note: These tests run without OpenSearch, so valid rules will return
    a config error. Full matching tests require OpenSearch integration tests.
    See test_rules_percolate.py for detailed percolate tests.
    """

    @pytest.mark.asyncio
    async def test_rule_test_without_opensearch(self, authenticated_client: AsyncClient):
        """Test rule returns config error when OpenSearch not available."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        sample_logs = [
            {"CommandLine": "cmd.exe /c whoami", "Image": "cmd.exe"},
            {"CommandLine": "notepad.exe", "Image": "notepad.exe"},
        ]
        response = await authenticated_client.post(
            "/api/rules/test",
            json={"yaml_content": yaml_content, "sample_logs": sample_logs},
        )
        assert response.status_code == 200
        data = response.json()
        # Without OpenSearch, should return config error
        assert len(data["errors"]) > 0
        assert data["errors"][0]["type"] == "config"
        assert "OpenSearch not configured" in data["errors"][0]["message"]

    @pytest.mark.asyncio
    async def test_rule_test_invalid_rule(self, authenticated_client: AsyncClient):
        """Test with invalid rule returns errors (before OpenSearch check)."""
        yaml_content = """
title: Test
  invalid: yaml
"""
        response = await authenticated_client.post(
            "/api/rules/test",
            json={"yaml_content": yaml_content, "sample_logs": [{"field": "value"}]},
        )
        assert response.status_code == 200
        data = response.json()
        # YAML validation errors should be returned before OpenSearch check
        assert len(data["errors"]) > 0
        assert len(data["matches"]) == 0

    @pytest.mark.asyncio
    async def test_rule_test_requires_auth(self, client: AsyncClient):
        """Test endpoint requires authentication."""
        response = await client.post(
            "/api/rules/test",
            json={"yaml_content": "title: Test", "sample_logs": []},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403


class TestRuleCRUD:
    """Tests for rule CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_rule(self, authenticated_client: AsyncClient):
        """Create a new rule."""
        # First create an index pattern (required for rules)
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        assert pattern_response.status_code == 201
        pattern_id = pattern_response.json()["id"]

        yaml_content = """
title: Test Detection Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": yaml_content,
                "index_pattern_id": pattern_id,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Test Rule"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_list_rules(self, authenticated_client: AsyncClient):
        """List all rules."""
        response = await authenticated_client.get("/api/rules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self, authenticated_client: AsyncClient):
        """Get non-existent rule returns 404."""
        response = await authenticated_client.get(
            "/api/rules/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_rule_requires_auth(self, client: AsyncClient):
        """Create rule requires authentication."""
        response = await client.post(
            "/api/rules",
            json={
                "title": "Test",
                "yaml_content": "title: Test",
                "index_pattern_id": "00000000-0000-0000-0000-000000000000",
            },
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403
