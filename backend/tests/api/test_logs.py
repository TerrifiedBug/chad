"""Tests for the logs API endpoints with authentication."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.main import app
from app.models.index_pattern import IndexPattern


class TestLogsEndpointAuth:
    """Tests for log shipping endpoint authentication."""

    @pytest.mark.asyncio
    async def test_receive_logs_without_token_rejected(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Log endpoint rejects requests without auth token."""
        # Create an index pattern with an auth token
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Auth Test Pattern",
                "pattern": "auth-test-*",
                "percolator_index": "chad-percolator-auth-test",
            },
        )
        assert create_response.status_code == 201

        # Try to send logs without auth token (unauthenticated client)
        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/logs/auth-test",
                json=[{"message": "test log"}],
            )
            assert response.status_code == 401
            assert "Missing authentication token" in response.json()["detail"]

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_receive_logs_with_invalid_token_rejected(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Log endpoint rejects requests with invalid auth token."""
        # Create an index pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Invalid Token Test",
                "pattern": "invalid-token-*",
                "percolator_index": "chad-percolator-invalid-token",
            },
        )
        assert create_response.status_code == 201

        # Try to send logs with wrong token
        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer wrong-token-here"},
        ) as client:
            response = await client.post(
                "/api/logs/invalid-token",
                json=[{"message": "test log"}],
            )
            assert response.status_code == 401
            assert "Invalid authentication token" in response.json()["detail"]

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_receive_logs_with_valid_token_accepted(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Log endpoint accepts requests with valid auth token."""
        # Create an index pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Valid Token Test",
                "pattern": "valid-token-*",
                "percolator_index": "chad-percolator-valid-token",
            },
        )
        assert create_response.status_code == 201
        auth_token = create_response.json()["auth_token"]

        # Send logs with correct token
        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {auth_token}"},
        ) as client:
            # This will fail with 503 (OpenSearch not configured) or
            # 404 (percolator index not found), but NOT 401 - that's the key
            response = await client.post(
                "/api/logs/valid-token",
                json=[{"message": "test log"}],
            )
            # Should get past auth check - expect 503 or 404, not 401
            assert response.status_code in [404, 503]

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_receive_logs_with_unknown_index_suffix(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Log endpoint returns 401 for unknown index suffix (no matching token)."""
        # Create a pattern so we have at least one in the database
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Some Pattern",
                "pattern": "some-*",
                "percolator_index": "chad-percolator-some",
            },
        )
        assert create_response.status_code == 201
        auth_token = create_response.json()["auth_token"]

        # Try to send logs to a different index suffix with this token
        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {auth_token}"},
        ) as client:
            response = await client.post(
                "/api/logs/nonexistent",
                json=[{"message": "test log"}],
            )
            # Should fail auth because this suffix doesn't match the token
            assert response.status_code == 401

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_test_endpoint_also_requires_auth(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Test endpoint also requires authentication."""
        # Create an index pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Endpoint Auth",
                "pattern": "test-endpoint-*",
                "percolator_index": "chad-percolator-test-endpoint",
            },
        )
        assert create_response.status_code == 201

        # Try test endpoint without auth
        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/logs/test-endpoint/test",
                json={"message": "test log"},
            )
            assert response.status_code == 401

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_test_endpoint_with_valid_token(
        self, test_session: AsyncSession, authenticated_client: AsyncClient
    ):
        """Test endpoint accepts valid auth token."""
        # Create an index pattern
        create_response = await authenticated_client.post(
            "/api/index-patterns",
            json={
                "name": "Test Endpoint Valid",
                "pattern": "test-valid-*",
                "percolator_index": "chad-percolator-test-valid",
            },
        )
        assert create_response.status_code == 201
        auth_token = create_response.json()["auth_token"]

        async def override():
            yield test_session

        app.dependency_overrides[get_db] = override

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {auth_token}"},
        ) as client:
            response = await client.post(
                "/api/logs/test-valid/test",
                json={"message": "test log"},
            )
            # Should get past auth check - expect 503 or 404, not 401
            assert response.status_code in [404, 503]

        app.dependency_overrides.clear()
