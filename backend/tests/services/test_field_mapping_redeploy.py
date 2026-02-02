import pytest

from app.services.field_mapping import get_rules_using_mapping


@pytest.mark.asyncio
async def test_get_rules_using_mapping(
    db_session,
    test_field_mapping,
    test_rule
):
    """Test finding rules that use a field mapping."""
    rules = await get_rules_using_mapping(db_session, test_field_mapping.id)

    assert len(rules) > 0
    assert test_rule in rules


@pytest.mark.asyncio
async def test_field_mapping_update_bumps_rule_version(
    authenticated_client,
    test_field_mapping,
    test_rule,
):
    """Test that updating a field mapping bumps rule versions."""
    # Get initial version
    result = await authenticated_client.get(
        f"/api/field-mappings/{test_field_mapping.id}"
    )
    initial_version = result.json()["version"]

    # Update field mapping (API uses PUT, not PATCH)
    response = await authenticated_client.put(
        f"/api/field-mappings/{test_field_mapping.id}",
        json={"target_field": "new_field"},
    )
    assert response.status_code == 200

    # Check mapping version incremented
    result = await authenticated_client.get(
        f"/api/field-mappings/{test_field_mapping.id}"
    )
    new_version = result.json()["version"]
    assert new_version == initial_version + 1
