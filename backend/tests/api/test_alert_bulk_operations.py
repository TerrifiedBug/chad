# backend/tests/api/test_alert_bulk_operations.py
"""Tests for alert bulk operations API endpoints."""

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_bulk_update_alert_status_unauthorized(
    async_client: AsyncClient,
):
    """Test bulk update requires authentication."""
    response = await async_client.patch(
        "/api/alerts/bulk/status",
        json={
            "alert_ids": [str(uuid.uuid4())],
            "status": "acknowledged"
        }
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_bulk_update_alert_status_forbidden(
    async_client: AsyncClient,
    normal_token: str
):
    """Test bulk update requires manage_rules permission."""
    response = await async_client.patch(
        "/api/alerts/bulk/status",
        headers={"Authorization": f"Bearer {normal_token}"},
        json={
            "alert_ids": [str(uuid.uuid4())],
            "status": "acknowledged"
        }
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_bulk_delete_alerts_unauthorized(
    async_client: AsyncClient,
):
    """Test bulk delete requires authentication."""
    response = await async_client.post(
        "/api/alerts/bulk/delete",
        json={"alert_ids": [str(uuid.uuid4())]}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_bulk_delete_alerts_forbidden(
    async_client: AsyncClient,
    normal_token: str
):
    """Test bulk delete requires manage_rules permission."""
    response = await async_client.post(
        "/api/alerts/bulk/delete",
        headers={"Authorization": f"Bearer {normal_token}"},
        json={"alert_ids": [str(uuid.uuid4())]}
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_delete_single_alert_unauthorized(
    async_client: AsyncClient,
):
    """Test delete requires authentication."""
    response = await async_client.delete(f"/api/alerts/{uuid.uuid4()}", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_single_alert_forbidden(
    async_client: AsyncClient,
    normal_token: str
):
    """Test delete requires manage_rules permission."""
    response = await async_client.delete(
        f"/api/alerts/{uuid.uuid4()}",
        json={},
        headers={"Authorization": f"Bearer {normal_token}"}
    )
    assert response.status_code == 403
