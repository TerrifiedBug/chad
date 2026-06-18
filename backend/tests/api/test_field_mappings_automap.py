"""Tests for deterministic preset auto-map + scorecard endpoints."""

import pytest
from httpx import AsyncClient

from app.api.deps import get_opensearch_client_optional
from app.main import app
from app.models.index_pattern import IndexPattern


class _FakeFields:
    """Sentinel; get_index_fields is monkeypatched, so the client is unused."""


@pytest.fixture
def fake_os_client():
    return _FakeFields()


@pytest.fixture(autouse=True)
def override_os_client(fake_os_client):
    app.dependency_overrides[get_opensearch_client_optional] = lambda: fake_os_client
    yield
    app.dependency_overrides.pop(get_opensearch_client_optional, None)


@pytest.mark.asyncio
async def test_auto_map_creates_preset_mappings(
    authenticated_client: AsyncClient,
    test_index_pattern: IndexPattern,
    monkeypatch,
):
    # Index has ECS fields available.
    monkeypatch.setattr(
        "app.api.field_mappings.get_index_fields",
        lambda client, pattern, include_multi_fields=True: {
            "source.ip",
            "destination.ip",
            "user.name",
        },
    )

    response = await authenticated_client.post(
        "/api/field-mappings/auto-map",
        json={
            "index_pattern_id": str(test_index_pattern.id),
            "sigma_fields": ["SourceIp", "DestinationIp", "User", "Nonexistent"],
            "family": "ecs",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mapped"] == 3
    methods = {r["sigma_field"]: r["method"] for r in body["results"]}
    assert methods["SourceIp"] == "preset"
    assert methods["Nonexistent"] == "none"


@pytest.mark.asyncio
async def test_auto_map_skips_already_mapped(
    authenticated_client: AsyncClient,
    test_index_pattern: IndexPattern,
    test_field_mapping,
    monkeypatch,
):
    # test_field_mapping fixture maps sigma_field "process.executable".
    monkeypatch.setattr(
        "app.api.field_mappings.get_index_fields",
        lambda client, pattern, include_multi_fields=True: {
            "process.executable",
            "source.ip",
        },
    )

    response = await authenticated_client.post(
        "/api/field-mappings/auto-map",
        json={
            "index_pattern_id": str(test_index_pattern.id),
            "sigma_fields": ["process.executable", "SourceIp"],
            "family": "ecs",
        },
    )
    assert response.status_code == 200
    body = response.json()
    # process.executable already mapped -> skipped; SourceIp newly mapped.
    assert body["skipped"] == 1
    assert body["mapped"] == 1


@pytest.mark.asyncio
async def test_scorecard_counts_resolvable(
    authenticated_client: AsyncClient,
    test_index_pattern: IndexPattern,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.field_mappings.get_index_fields",
        lambda client, pattern, include_multi_fields=True: {
            "source.ip",
            "user.name",
        },
    )

    response = await authenticated_client.post(
        "/api/field-mappings/scorecard",
        json={
            "index_pattern_id": str(test_index_pattern.id),
            "sigma_fields": ["SourceIp", "User", "Image"],
            "family": "ecs",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["resolvable"] == 2
    assert body["family"] == "ecs"
