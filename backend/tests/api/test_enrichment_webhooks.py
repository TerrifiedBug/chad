"""Tests for enrichment webhook API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import encrypt
from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.enrichment_webhook import EnrichmentWebhook
from app.models.user import User, UserRole


@pytest_asyncio.fixture(scope="function")
async def non_admin_user(test_session: AsyncSession) -> User:
    """Create a non-admin test user."""
    user = User(
        id=uuid.uuid4(),
        email="viewer@example.com",
        password_hash=get_password_hash("viewerpassword"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def non_admin_token(non_admin_user: User) -> str:
    """Create a JWT token for the non-admin user."""
    return create_access_token(data={"sub": str(non_admin_user.id)})


@pytest_asyncio.fixture(scope="function")
async def non_admin_client(test_session: AsyncSession, non_admin_token: str):
    """Create an authenticated test client for a non-admin user."""
    async def override():
        yield test_session

    app.dependency_overrides[get_db] = override

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {non_admin_token}"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def sample_webhook(test_session: AsyncSession) -> EnrichmentWebhook:
    """Create a sample enrichment webhook."""
    webhook = EnrichmentWebhook(
        id=uuid.uuid4(),
        name="Test Webhook",
        url="https://example.com/api/enrich",
        namespace="test_namespace",
        method="POST",
        timeout_seconds=30,
        max_concurrent_calls=5,
        cache_ttl_seconds=300,
        is_active=True,
    )
    test_session.add(webhook)
    await test_session.commit()
    await test_session.refresh(webhook)
    return webhook


@pytest_asyncio.fixture(scope="function")
async def sample_webhook_with_creds(test_session: AsyncSession) -> EnrichmentWebhook:
    """Create a sample enrichment webhook with encrypted credentials."""
    webhook = EnrichmentWebhook(
        id=uuid.uuid4(),
        name="Webhook With Auth",
        url="https://example.com/api/secure",
        namespace="secure_namespace",
        method="POST",
        header_name="Authorization",
        header_value_encrypted=encrypt("Bearer secret-token"),
        timeout_seconds=30,
        max_concurrent_calls=5,
        cache_ttl_seconds=300,
        is_active=True,
    )
    test_session.add(webhook)
    await test_session.commit()
    await test_session.refresh(webhook)
    return webhook


class TestListEnrichmentWebhooks:
    """Tests for GET /enrichment-webhooks endpoint."""

    @pytest.mark.asyncio
    async def test_list_requires_auth(self, client: AsyncClient):
        """List endpoint requires authentication."""
        response = await client.get("/api/enrichment-webhooks")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_requires_admin(self, non_admin_client: AsyncClient):
        """List endpoint requires admin role."""
        response = await non_admin_client.get("/api/enrichment-webhooks")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_empty(self, authenticated_client: AsyncClient):
        """List returns empty when no webhooks exist."""
        response = await authenticated_client.get("/api/enrichment-webhooks")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_list_with_webhooks(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """List returns webhooks."""
        response = await authenticated_client.get("/api/enrichment-webhooks")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Test Webhook"
        assert data[0]["namespace"] == "test_namespace"
        assert data[0]["has_credentials"] is False


class TestCreateEnrichmentWebhook:
    """Tests for POST /enrichment-webhooks endpoint."""

    @pytest.mark.asyncio
    async def test_create_requires_auth(self, client: AsyncClient):
        """Create endpoint requires authentication."""
        response = await client.post(
            "/api/enrichment-webhooks",
            json={"name": "Test", "url": "https://example.com", "namespace": "test"},
        )
        # Returns 403 due to CSRF protection or 401 from HTTPBearer
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_create_requires_admin(self, non_admin_client: AsyncClient):
        """Create endpoint requires admin role."""
        response = await non_admin_client.post(
            "/api/enrichment-webhooks",
            json={"name": "Test", "url": "https://example.com", "namespace": "test"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_create_webhook_success(self, authenticated_client: AsyncClient):
        """Successfully create a webhook."""
        response = await authenticated_client.post(
            "/api/enrichment-webhooks",
            json={
                "name": "Entra ID Enrichment",
                "url": "https://api.example.com/enrich",
                "namespace": "entraid",
                "method": "POST",
                "timeout_seconds": 30,
                "cache_ttl_seconds": 600,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Entra ID Enrichment"
        assert data["namespace"] == "entraid"
        assert data["url"] == "https://api.example.com/enrich"
        assert data["has_credentials"] is False
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_webhook_with_credentials(self, authenticated_client: AsyncClient):
        """Create webhook with authentication credentials."""
        response = await authenticated_client.post(
            "/api/enrichment-webhooks",
            json={
                "name": "Secure Webhook",
                "url": "https://api.example.com/secure",
                "namespace": "secure",
                "header_name": "X-API-Key",
                "header_value": "supersecret123",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["header_name"] == "X-API-Key"
        assert data["has_credentials"] is True
        # Verify credentials are not returned in response
        assert "header_value" not in data
        assert "header_value_encrypted" not in data

    @pytest.mark.asyncio
    async def test_create_webhook_invalid_namespace(self, authenticated_client: AsyncClient):
        """Reject invalid namespace format."""
        response = await authenticated_client.post(
            "/api/enrichment-webhooks",
            json={
                "name": "Test",
                "url": "https://example.com",
                "namespace": "invalid namespace!",  # Contains space and special char
            },
        )
        assert response.status_code == 422
        # Pydantic validation error

    @pytest.mark.asyncio
    async def test_create_webhook_ssrf_blocked(self, authenticated_client: AsyncClient):
        """Block SSRF attempts to internal IPs."""
        response = await authenticated_client.post(
            "/api/enrichment-webhooks",
            json={
                "name": "Internal Webhook",
                "url": "http://127.0.0.1:8080/secret",
                "namespace": "internal",
            },
        )
        assert response.status_code == 400
        assert "SSRF" in response.json()["detail"] or "Invalid" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_duplicate_namespace_rejected(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """Reject duplicate namespace."""
        response = await authenticated_client.post(
            "/api/enrichment-webhooks",
            json={
                "name": "Another Webhook",
                "url": "https://other.example.com",
                "namespace": "test_namespace",  # Already exists in sample_webhook
            },
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]


class TestGetEnrichmentWebhook:
    """Tests for GET /enrichment-webhooks/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_webhook(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """Get a specific webhook."""
        response = await authenticated_client.get(
            f"/api/enrichment-webhooks/{sample_webhook.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(sample_webhook.id)
        assert data["name"] == sample_webhook.name

    @pytest.mark.asyncio
    async def test_get_webhook_not_found(self, authenticated_client: AsyncClient):
        """Return 404 for non-existent webhook."""
        random_id = uuid.uuid4()
        response = await authenticated_client.get(f"/api/enrichment-webhooks/{random_id}")
        assert response.status_code == 404


class TestUpdateEnrichmentWebhook:
    """Tests for PATCH /enrichment-webhooks/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_webhook(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """Update a webhook."""
        response = await authenticated_client.patch(
            f"/api/enrichment-webhooks/{sample_webhook.id}",
            json={"name": "Updated Name", "cache_ttl_seconds": 600},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["cache_ttl_seconds"] == 600

    @pytest.mark.asyncio
    async def test_update_webhook_add_credentials(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """Add credentials to existing webhook."""
        response = await authenticated_client.patch(
            f"/api/enrichment-webhooks/{sample_webhook.id}",
            json={
                "header_name": "Authorization",
                "header_value": "Bearer new-token",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["header_name"] == "Authorization"
        assert data["has_credentials"] is True

    @pytest.mark.asyncio
    async def test_update_webhook_not_found(self, authenticated_client: AsyncClient):
        """Return 404 for non-existent webhook."""
        random_id = uuid.uuid4()
        response = await authenticated_client.patch(
            f"/api/enrichment-webhooks/{random_id}",
            json={"name": "Updated"},
        )
        assert response.status_code == 404


class TestDeleteEnrichmentWebhook:
    """Tests for DELETE /enrichment-webhooks/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_webhook(
        self, authenticated_client: AsyncClient, sample_webhook: EnrichmentWebhook
    ):
        """Delete a webhook."""
        response = await authenticated_client.delete(
            f"/api/enrichment-webhooks/{sample_webhook.id}"
        )
        assert response.status_code == 204

        # Verify deleted
        response = await authenticated_client.get(
            f"/api/enrichment-webhooks/{sample_webhook.id}"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_webhook_not_found(self, authenticated_client: AsyncClient):
        """Return 404 for non-existent webhook."""
        random_id = uuid.uuid4()
        response = await authenticated_client.delete(f"/api/enrichment-webhooks/{random_id}")
        assert response.status_code == 404


class TestWebhookCredentialsSecurity:
    """Tests for credential handling security."""

    @pytest.mark.asyncio
    async def test_credentials_not_exposed_in_list(
        self, authenticated_client: AsyncClient, sample_webhook_with_creds: EnrichmentWebhook
    ):
        """Ensure credentials are never exposed in list response."""
        response = await authenticated_client.get("/api/enrichment-webhooks")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["has_credentials"] is True
        assert "header_value" not in data[0]
        assert "header_value_encrypted" not in data[0]

    @pytest.mark.asyncio
    async def test_credentials_not_exposed_in_get(
        self, authenticated_client: AsyncClient, sample_webhook_with_creds: EnrichmentWebhook
    ):
        """Ensure credentials are never exposed in get response."""
        response = await authenticated_client.get(
            f"/api/enrichment-webhooks/{sample_webhook_with_creds.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credentials"] is True
        assert "header_value" not in data
        assert "header_value_encrypted" not in data
