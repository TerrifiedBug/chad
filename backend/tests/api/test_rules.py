"""Tests for the rules API endpoints."""

import pytest
from httpx import AsyncClient

from app.models.index_pattern import IndexPattern
from app.models.notification_settings import NotificationSettings
from app.models.rule import RuleStatus


class TestStatusModelSimplification:
    """Test the new DEPLOYED/UNDEPLOYED/SNOOZED status model."""

    @pytest.mark.asyncio
    async def test_cannot_snooze_undeployed_rule(self, authenticated_client: AsyncClient, test_session):
        """Snooze should fail for undeployed rules."""
        # Create index pattern first
        pattern = IndexPattern(
            name="test-snooze-pattern",
            pattern="test-snooze-*",
            percolator_index="percolator-test-snooze"
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)

        # Create rule (starts as undeployed)
        response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Snooze Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "severity": "medium",
                "index_pattern_id": str(pattern.id)
            }
        )
        assert response.status_code == 201
        rule_id = response.json()["id"]

        # Try to snooze - should fail because rule is undeployed
        response = await authenticated_client.post(
            f"/api/rules/{rule_id}/snooze",
            json={"hours": 24}
        )
        assert response.status_code == 400
        assert "cannot snooze" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_status_enum_values(self):
        """Verify the new status enum values exist."""
        assert hasattr(RuleStatus, 'DEPLOYED')
        assert hasattr(RuleStatus, 'UNDEPLOYED')
        assert hasattr(RuleStatus, 'SNOOZED')
        # Old values should not exist
        assert not hasattr(RuleStatus, 'ENABLED')


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

    @pytest.mark.asyncio
    async def test_create_rule_has_initial_version_reason(self, authenticated_client: AsyncClient):
        """Verify new rules have 'Initial version' change reason."""
        # Create index pattern
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

        # Create rule
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
        rule_id = data["id"]

        # Get rule details to check version history
        response = await authenticated_client.get(f"/api/rules/{rule_id}")
        assert response.status_code == 200
        rule_detail = response.json()

        # Verify version history has change_reason
        assert len(rule_detail["versions"]) > 0
        first_version = rule_detail["versions"][0]
        assert first_version["change_reason"] == "Initial version"
        assert "changed_by" in first_version

    @pytest.mark.asyncio
    async def test_update_rule_with_change_reason(self, authenticated_client: AsyncClient):
        """Verify change_reason is stored when provided."""
        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Update rule with change_reason
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
                "change_reason": "Fixed detection logic",
            },
        )
        assert response.status_code == 200

        # Verify change_reason in version history
        response = await authenticated_client.get(f"/api/rules/{rule_id}")
        assert response.status_code == 200
        rule_detail = response.json()

        # Should have 2 versions now
        assert len(rule_detail["versions"]) == 2
        latest_version = rule_detail["versions"][0]  # Most recent is first
        assert latest_version["change_reason"] == "Fixed detection logic"
        assert latest_version["yaml_content"] == new_yaml

    @pytest.mark.asyncio
    async def test_update_rule_without_change_reason_uses_default(self, authenticated_client: AsyncClient):
        """Verify default change_reason when not provided."""
        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Update rule WITHOUT change_reason
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
            },
        )
        assert response.status_code == 200

        # Verify default change_reason in version history
        response = await authenticated_client.get(f"/api/rules/{rule_id}")
        assert response.status_code == 200
        rule_detail = response.json()

        # Should have 2 versions
        assert len(rule_detail["versions"]) == 2
        latest_version = rule_detail["versions"][0]
        assert latest_version["change_reason"] == "Rule updated"
        assert latest_version["yaml_content"] == new_yaml


class TestMandatoryComments:
    """Tests for mandatory change_reason validation."""

    @pytest.mark.asyncio
    async def test_update_rule_without_change_reason_when_mandatory_enabled_all_rules(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that rule update fails when change_reason missing and mandatory comments enabled for all rules."""
        # Enable mandatory comments for all rules
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=False)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Try to update rule WITHOUT change_reason - should fail
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
            },
        )
        assert response.status_code == 400
        assert "Change reason is required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_rule_without_change_reason_when_mandatory_enabled_deployed_only(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that undeployed rule can be updated without change_reason when mandatory is deployed-only."""
        # Enable mandatory comments for deployed rules only
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=True)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and undeployed rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
                "status": "undeployed",  # Explicitly undeployed
            },
        )
        rule_id = create_response.json()["id"]

        # Try to update undeployed rule WITHOUT change_reason - should succeed
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_deployed_rule_without_change_reason_when_mandatory_enabled_deployed_only(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that deployed rule update fails when change_reason missing and mandatory is deployed-only."""
        # Enable mandatory comments for deployed rules only
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=True)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and deployed rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
                "status": "deployed",  # Deployed rule
            },
        )
        rule_id = create_response.json()["id"]

        # Try to update deployed rule WITHOUT change_reason - should fail
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
            },
        )
        assert response.status_code == 400
        assert "Change reason is required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_rule_with_change_reason_when_mandatory_enabled(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that rule update succeeds when change_reason is provided and mandatory comments enabled."""
        # Enable mandatory comments
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=False)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Update rule WITH change_reason - should succeed
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
                "change_reason": "Fixed detection logic to include EventID 2",
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_rule_without_change_reason_when_mandatory_disabled(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that rule update succeeds without change_reason when mandatory comments disabled."""
        # Disable mandatory comments
        settings = NotificationSettings(mandatory_rule_comments=False, mandatory_comments_deployed_only=False)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Update rule WITHOUT change_reason - should succeed
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_rule_with_empty_change_reason_when_mandatory_enabled(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that rule update fails when change_reason is empty string and mandatory comments enabled."""
        # Enable mandatory comments
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=False)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Try to update rule with empty change_reason - should fail
        new_yaml = "title: Updated Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 2\n  condition: selection"
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "yaml_content": new_yaml,
                "change_reason": "   ",  # Whitespace only
            },
        )
        assert response.status_code == 400
        assert "Change reason is required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_rule_non_yaml_fields_without_change_reason_when_mandatory_enabled(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that updating non-yaml fields doesn't require change_reason even when mandatory enabled."""
        # Enable mandatory comments
        settings = NotificationSettings(mandatory_rule_comments=True, mandatory_comments_deployed_only=False)
        test_session.add(settings)
        await test_session.commit()

        # Create index pattern and rule
        pattern_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Index Pattern",
                "pattern": "logs-*",
                "percolator_index": "percolator-logs",
            },
        )
        pattern_id = pattern_response.json()["id"]

        create_response = await authenticated_client.post(
            "/api/rules",
            json={
                "title": "Test Rule",
                "yaml_content": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                "index_pattern_id": pattern_id,
            },
        )
        rule_id = create_response.json()["id"]

        # Update rule title (not yaml_content) WITHOUT change_reason - should succeed
        response = await authenticated_client.patch(
            f"/api/rules/{rule_id}",
            json={
                "title": "Updated Title",
                "description": "Updated description",
            },
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_get_index_pattern_fields(
    authenticated_client: AsyncClient,
    test_session,
):
    """Test getting index pattern fields for exceptions dropdown."""
    from unittest.mock import patch, Mock
    from app.models.index_pattern import IndexPattern

    # Create index pattern directly (not using API to avoid permission issues)
    index_pattern = IndexPattern(
        name="logs-test",
        pattern="logs-test-*",
        percolator_index="percolator-logs-test",
        auth_token="test-token",
    )
    test_session.add(index_pattern)
    await test_session.commit()
    await test_session.refresh(index_pattern)

    # Mock OpenSearch response
    mock_os = Mock()
    mock_os.indices.get_mapping.return_value = {
        "logs-test-2024-01-01": {
            "mappings": {
                "properties": {
                    "host": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "process": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "keyword"},
                            "exec": {"type": "text"},
                        },
                    },
                },
            }
        }
    }

    # Patch get_opensearch_client
    with patch("app.api.rules.get_opensearch_client", return_value=mock_os):
        response = await authenticated_client.get(
            f"/api/rules/index-fields/{index_pattern.id}",
        )

    assert response.status_code == 200
    data = response.json()
    assert "fields" in data
    assert set(data["fields"]) == {"host", "user", "process.name", "process.exec"}
    assert data["fields"] == sorted(data["fields"])  # Verify sorted

