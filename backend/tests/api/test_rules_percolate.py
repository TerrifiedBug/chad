"""Tests for rule testing with OpenSearch percolate."""

import pytest
from httpx import AsyncClient


class TestRulePercolate:
    """Tests for POST /rules/test endpoint with percolate."""

    @pytest.mark.asyncio
    async def test_test_rule_without_opensearch(self, authenticated_client: AsyncClient):
        """Test that test_rule returns error when OpenSearch not configured."""
        response = await authenticated_client.post(
            "/api/rules/test",
            json={
                "yaml_content": """
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
""",
                "sample_logs": [{"EventID": 1}],
            },
        )

        # Without OpenSearch, should return config error
        assert response.status_code == 200
        data = response.json()
        assert len(data["errors"]) > 0
        assert data["errors"][0]["type"] == "config"
        assert "OpenSearch not configured" in data["errors"][0]["message"]

    @pytest.mark.asyncio
    async def test_test_rule_requires_auth(self, client: AsyncClient):
        """Test endpoint requires authentication."""
        response = await client.post(
            "/api/rules/test",
            json={
                "yaml_content": """
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
""",
                "sample_logs": [{"EventID": 1}],
            },
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_test_rule_invalid_yaml(self, authenticated_client: AsyncClient):
        """Test that invalid YAML returns validation errors (before OpenSearch check)."""
        response = await authenticated_client.post(
            "/api/rules/test",
            json={
                "yaml_content": """
title: Test
  invalid: yaml
""",
                "sample_logs": [{"field": "value"}],
            },
        )

        assert response.status_code == 200
        data = response.json()
        # Should get YAML/Sigma validation errors before OpenSearch check
        assert len(data["errors"]) > 0
        assert len(data["matches"]) == 0
