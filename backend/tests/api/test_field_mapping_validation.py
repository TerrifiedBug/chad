import pytest
from httpx import AsyncClient
from app.models.user import User
from app.models.index_pattern import IndexPattern


@pytest.mark.asyncio
async def test_create_mapping_with_valid_field(
    client: AsyncClient,
    test_user: User,
    test_index_pattern: IndexPattern,
):
    """Test creating a mapping with a valid field."""
    # Create mapping with valid field
    response = await client.post("/api/field-mappings", json={
        "sigma_field": "process.executable",
        "target_field": "process.executable",
        "index_pattern_id": str(test_index_pattern.id)
    })
    assert response.status_code == 201
    assert response.json()["target_field"] == "process.executable"


@pytest.mark.asyncio
async def test_create_mapping_with_invalid_field(
    client: AsyncClient,
    test_user: User,
    test_index_pattern: IndexPattern,
):
    """Test creating a mapping with invalid field returns 400."""
    # Try to create mapping with invalid field
    response = await client.post("/api/field-mappings", json={
        "sigma_field": "process.executable",
        "target_field": "fake_field_xyz",
        "index_pattern_id": str(test_index_pattern.id)
    })
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "field_not_found"
    assert "fake_field_xyz" in detail["field"]
    assert isinstance(detail["suggestions"], list)


@pytest.mark.asyncio
async def test_validation_suggests_similar_fields(
    client: AsyncClient,
    test_user: User,
    test_index_pattern: IndexPattern,
):
    """Test that validation suggests similar fields."""
    # Create mapping with typo (e.g., "process.exe" instead of "process.executable")
    response = await client.post("/api/field-mappings", json={
        "sigma_field": "process.command_line",
        "target_field": "process.exe",  # Typo
        "index_pattern_id": str(test_index_pattern.id)
    })
    assert response.status_code == 400
    suggestions = response.json()["detail"]["suggestions"]
    assert len(suggestions) > 0
    # Should suggest "process.executable" or similar
    assert any("executable" in s for s in suggestions)
