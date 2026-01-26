"""Tests for correlation rules audit logging."""

import pytest


@pytest.mark.asyncio
async def test_correlation_rule_created_audit_log(authenticated_client):
    """Test that creating a correlation rule creates an audit log."""
    # Create index pattern first (required for rules)
    pattern_response = await authenticated_client.post(
        "/api/index-patterns",
        json={
            "name": "Test Index Pattern for Correlation",
            "pattern": "test-correlation-*",
            "percolator_index": "percolator-test-correlation",
        },
    )
    assert pattern_response.status_code == 201
    pattern_id = pattern_response.json()["id"]

    yaml_content = """
title: Test Detection Rule A
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""
    # Create two test rules first
    rule_a_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule A for Correlation",
            "yaml_content": yaml_content,
            "index_pattern_id": pattern_id,
        },
    )
    assert rule_a_response.status_code == 201
    rule_a_id = rule_a_response.json()["id"]

    yaml_content_b = """
title: Test Detection Rule B
logsource:
    product: windows
detection:
    selection:
        EventID: 2
    condition: selection
"""
    rule_b_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule B for Correlation",
            "yaml_content": yaml_content_b,
            "index_pattern_id": pattern_id,
        },
    )
    assert rule_b_response.status_code == 201
    rule_b_id = rule_b_response.json()["id"]

    # Create correlation rule
    response = await authenticated_client.post(
        "/api/correlation-rules",
        json={
            "name": "Test Correlation",
            "rule_a_id": rule_a_id,
            "rule_b_id": rule_b_id,
            "entity_field": "process.entity_id",
            "time_window_minutes": 5,
            "severity": "high",
            "is_enabled": True,
        },
    )

    assert response.status_code == 200
    correlation_id = response.json()["id"]

    # Check audit log
    audit_response = await authenticated_client.get(
        f"/api/audit?entity_id=correlation_rule:{correlation_id}",
    )

    assert audit_response.status_code == 200
    items = audit_response.json()["items"]
    assert len(items) >= 1
    assert items[0]["action"] == "correlation_rule_created"
    # entity_id not included in response schema
    assert items[0]["details"]["name"] == "Test Correlation"
    assert items[0]["details"]["severity"] == "high"


@pytest.mark.asyncio
async def test_correlation_rule_updated_audit_log(authenticated_client):
    """Test that updating a correlation rule creates an audit log."""
    # Create index pattern
    pattern_response = await authenticated_client.post(
        "/api/index-patterns",
        json={
            "name": "Test Index Pattern for Update",
            "pattern": "test-update-*",
            "percolator_index": "percolator-test-update",
        },
    )
    pattern_id = pattern_response.json()["id"]

    # Create two test rules
    yaml_content_a = """
title: Test Rule A Update
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""
    rule_a_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule A for Update",
            "yaml_content": yaml_content_a,
            "index_pattern_id": pattern_id,
        },
    )
    rule_a_id = rule_a_response.json()["id"]

    yaml_content_b = """
title: Test Rule B Update
logsource:
    product: windows
detection:
    selection:
        EventID: 2
    condition: selection
"""
    rule_b_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule B for Update",
            "yaml_content": yaml_content_b,
            "index_pattern_id": pattern_id,
        },
    )
    rule_b_id = rule_b_response.json()["id"]

    # Create correlation rule
    create_response = await authenticated_client.post(
        "/api/correlation-rules",
        json={
            "name": "Test Correlation Update",
            "rule_a_id": rule_a_id,
            "rule_b_id": rule_b_id,
            "entity_field": "process.entity_id",
            "time_window_minutes": 5,
            "severity": "high",
            "is_enabled": True,
        },
    )
    correlation_id = create_response.json()["id"]

    # Update correlation rule
    update_response = await authenticated_client.patch(
        f"/api/correlation-rules/{correlation_id}",
        json={
            "name": "Updated Correlation Name",
            "time_window_minutes": 10,
        },
    )

    assert update_response.status_code == 200

    # Check audit log
    audit_response = await authenticated_client.get(
        f"/api/audit?entity_id=correlation_rule:{correlation_id}",
    )

    assert audit_response.status_code == 200
    items = audit_response.json()["items"]
    update_events = [item for item in items if item["action"] == "correlation_rule_updated"]
    assert len(update_events) >= 1
    assert update_events[0]["details"]["name"] == "Updated Correlation Name"
    assert "changes" in update_events[0]["details"]
    assert "name" in update_events[0]["details"]["changes"]
    assert "time_window_minutes" in update_events[0]["details"]["changes"]


@pytest.mark.asyncio
async def test_correlation_rule_deleted_audit_log(authenticated_client):
    """Test that deleting a correlation rule creates an audit log."""
    # Create index pattern
    pattern_response = await authenticated_client.post(
        "/api/index-patterns",
        json={
            "name": "Test Index Pattern for Delete",
            "pattern": "test-delete-*",
            "percolator_index": "percolator-test-delete",
        },
    )
    pattern_id = pattern_response.json()["id"]

    # Create two test rules
    yaml_content_a = """
title: Test Rule A Delete
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""
    rule_a_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule A for Delete",
            "yaml_content": yaml_content_a,
            "index_pattern_id": pattern_id,
        },
    )
    rule_a_id = rule_a_response.json()["id"]

    yaml_content_b = """
title: Test Rule B Delete
logsource:
    product: windows
detection:
    selection:
        EventID: 2
    condition: selection
"""
    rule_b_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule B for Delete",
            "yaml_content": yaml_content_b,
            "index_pattern_id": pattern_id,
        },
    )
    rule_b_id = rule_b_response.json()["id"]

    # Create correlation rule
    create_response = await authenticated_client.post(
        "/api/correlation-rules",
        json={
            "name": "Test Correlation Delete",
            "rule_a_id": rule_a_id,
            "rule_b_id": rule_b_id,
            "entity_field": "process.entity_id",
            "time_window_minutes": 5,
            "severity": "high",
            "is_enabled": True,
        },
    )
    correlation_id = create_response.json()["id"]

    # Delete correlation rule
    delete_response = await authenticated_client.delete(
        f"/api/correlation-rules/{correlation_id}",
    )

    assert delete_response.status_code == 200

    # Check audit log - search by action since entity is deleted
    audit_response = await authenticated_client.get(
        "/api/audit?action=correlation_rule_deleted&limit=10",
    )

    assert audit_response.status_code == 200
    items = audit_response.json()["items"]
    delete_events = [item for item in items if item["action"] == "correlation_rule_deleted"]
    assert len(delete_events) >= 1
    assert delete_events[0]["details"]["name"] == "Test Correlation Delete"


@pytest.mark.asyncio
async def test_correlation_rule_toggled_audit_log(authenticated_client):
    """Test that toggling a correlation rule creates an audit log."""
    # Create index pattern
    pattern_response = await authenticated_client.post(
        "/api/index-patterns",
        json={
            "name": "Test Index Pattern for Toggle",
            "pattern": "test-toggle-*",
            "percolator_index": "percolator-test-toggle",
        },
    )
    pattern_id = pattern_response.json()["id"]

    # Create two test rules
    yaml_content_a = """
title: Test Rule A Toggle
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""
    rule_a_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule A for Toggle",
            "yaml_content": yaml_content_a,
            "index_pattern_id": pattern_id,
        },
    )
    rule_a_id = rule_a_response.json()["id"]

    yaml_content_b = """
title: Test Rule B Toggle
logsource:
    product: windows
detection:
    selection:
        EventID: 2
    condition: selection
"""
    rule_b_response = await authenticated_client.post(
        "/api/rules",
        json={
            "title": "Test Rule B for Toggle",
            "yaml_content": yaml_content_b,
            "index_pattern_id": pattern_id,
        },
    )
    rule_b_id = rule_b_response.json()["id"]

    # Create correlation rule
    create_response = await authenticated_client.post(
        "/api/correlation-rules",
        json={
            "name": "Test Correlation Toggle",
            "rule_a_id": rule_a_id,
            "rule_b_id": rule_b_id,
            "entity_field": "process.entity_id",
            "time_window_minutes": 5,
            "severity": "high",
            "is_enabled": True,
        },
    )
    correlation_id = create_response.json()["id"]

    # Disable correlation rule
    disable_response = await authenticated_client.patch(
        f"/api/correlation-rules/{correlation_id}/toggle",
        params={"enabled": False},
    )

    assert disable_response.status_code == 200
    assert disable_response.json()["is_enabled"] is False

    # Check audit log
    audit_response = await authenticated_client.get(
        f"/api/audit?entity_id=correlation_rule:{correlation_id}",
    )

    assert audit_response.status_code == 200
    items = audit_response.json()["items"]
    disable_events = [item for item in items if item["action"] == "correlation_rule_disabled"]
    assert len(disable_events) >= 1
    assert disable_events[0]["details"]["enabled"] is False

    # Enable correlation rule
    enable_response = await authenticated_client.patch(
        f"/api/correlation-rules/{correlation_id}/toggle",
        params={"enabled": True},
    )

    assert enable_response.status_code == 200
    assert enable_response.json()["is_enabled"] is True

    # Check audit log for enable event
    audit_response = await authenticated_client.get(
        f"/api/audit?entity_id=correlation_rule:{correlation_id}",
    )

    items = audit_response.json()["items"]
    enable_events = [item for item in items if item["action"] == "correlation_rule_enabled"]
    assert len(enable_events) >= 1
    assert enable_events[0]["details"]["enabled"] is True
