# backend/tests/api/test_audit.py
"""Tests for the Audit Log API endpoints."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.audit_log import AuditLog
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
async def sample_audit_logs(test_session: AsyncSession, test_user: User) -> list[AuditLog]:
    """Create sample audit log entries for testing."""
    logs = []
    base_time = datetime.now(timezone.utc)

    # Create a variety of audit log entries
    log_data = [
        ("create", "rule", "rule-001", {"title": "Test Rule 1"}),
        ("update", "rule", "rule-001", {"changed_fields": ["yaml_content"]}),
        ("delete", "rule", "rule-002", {"title": "Deleted Rule"}),
        ("create", "user", "user-001", {"email": "new@example.com"}),
        ("login", "session", None, {"ip_address": "192.168.1.1"}),
        ("deploy", "rule", "rule-001", {"index_pattern": "logs-*"}),
    ]

    for i, (action, resource_type, resource_id, details) in enumerate(log_data):
        log = AuditLog(
            id=uuid.uuid4(),
            user_id=test_user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            created_at=base_time - timedelta(minutes=i * 10),
        )
        test_session.add(log)
        logs.append(log)

    # Add one log without a user_id (system action)
    system_log = AuditLog(
        id=uuid.uuid4(),
        user_id=None,
        action="scheduled_task",
        resource_type="system",
        resource_id=None,
        details={"task": "cleanup"},
        created_at=base_time - timedelta(hours=1),
    )
    test_session.add(system_log)
    logs.append(system_log)

    await test_session.commit()
    return logs


class TestListAuditLogs:
    """Tests for GET /audit endpoint."""

    @pytest.mark.asyncio
    async def test_list_requires_auth(self, client: AsyncClient):
        """List endpoint requires authentication."""
        response = await client.get("/api/audit")
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_requires_admin(self, non_admin_client: AsyncClient):
        """List endpoint requires admin role."""
        response = await non_admin_client.get("/api/audit")
        assert response.status_code == 403
        assert "Admin access required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_empty(self, authenticated_client: AsyncClient):
        """List returns empty when no logs exist."""
        response = await authenticated_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["limit"] == 50
        assert data["offset"] == 0

    @pytest.mark.asyncio
    async def test_list_with_logs(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog], test_user: User
    ):
        """List returns audit log entries with user emails."""
        response = await authenticated_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == len(sample_audit_logs)
        assert len(data["items"]) == len(sample_audit_logs)

        # First item should be the most recent (ordered by created_at desc)
        first_item = data["items"][0]
        assert first_item["action"] == "create"
        assert first_item["resource_type"] == "rule"
        assert first_item["user_email"] == test_user.email

        # System log should have no user_email
        system_log_item = next(
            (item for item in data["items"] if item["action"] == "scheduled_task"), None
        )
        assert system_log_item is not None
        assert system_log_item["user_email"] is None
        assert system_log_item["user_id"] is None

    @pytest.mark.asyncio
    async def test_list_pagination(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """List supports pagination."""
        # Get first page
        response = await authenticated_client.get("/api/audit?limit=3&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 3
        assert data["total"] == len(sample_audit_logs)
        assert data["limit"] == 3
        assert data["offset"] == 0

        # Get second page
        response = await authenticated_client.get("/api/audit?limit=3&offset=3")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 3
        assert data["total"] == len(sample_audit_logs)
        assert data["offset"] == 3

    @pytest.mark.asyncio
    async def test_filter_by_action(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """List can filter by action."""
        response = await authenticated_client.get("/api/audit?action=create")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2  # rule create and user create
        for item in data["items"]:
            assert item["action"] == "create"

    @pytest.mark.asyncio
    async def test_filter_by_resource_type(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """List can filter by resource_type."""
        response = await authenticated_client.get("/api/audit?resource_type=rule")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 4  # create, update, delete, deploy
        for item in data["items"]:
            assert item["resource_type"] == "rule"

    @pytest.mark.asyncio
    async def test_filter_by_user_id(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog], test_user: User
    ):
        """List can filter by user_id."""
        response = await authenticated_client.get(f"/api/audit?user_id={test_user.id}")
        assert response.status_code == 200
        data = response.json()
        # Should exclude the system log (no user_id)
        assert data["total"] == len(sample_audit_logs) - 1
        for item in data["items"]:
            assert item["user_id"] == str(test_user.id)

    @pytest.mark.asyncio
    async def test_filter_by_date_range(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """List can filter by date range."""
        now = datetime.now(timezone.utc)
        # Use a simple ISO format without timezone suffix for URL compatibility
        start_date = (now - timedelta(minutes=35)).strftime("%Y-%m-%dT%H:%M:%S")
        end_date = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")

        response = await authenticated_client.get(
            f"/api/audit?start_date={start_date}&end_date={end_date}"
        )
        assert response.status_code == 200
        data = response.json()
        # Should match logs created between 35 and 5 minutes ago
        # That's logs at 10, 20, 30 minutes ago (index 1, 2, 3)
        assert data["total"] == 3

    @pytest.mark.asyncio
    async def test_combined_filters(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """List can combine multiple filters."""
        response = await authenticated_client.get(
            "/api/audit?action=create&resource_type=rule"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1  # Only the rule create
        assert data["items"][0]["action"] == "create"
        assert data["items"][0]["resource_type"] == "rule"


class TestListAuditActions:
    """Tests for GET /audit/actions endpoint."""

    @pytest.mark.asyncio
    async def test_actions_requires_auth(self, client: AsyncClient):
        """Actions endpoint requires authentication."""
        response = await client.get("/api/audit/actions")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_actions_requires_admin(self, non_admin_client: AsyncClient):
        """Actions endpoint requires admin role."""
        response = await non_admin_client.get("/api/audit/actions")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_actions_empty(self, authenticated_client: AsyncClient):
        """Actions returns empty list when no logs exist."""
        response = await authenticated_client.get("/api/audit/actions")
        assert response.status_code == 200
        data = response.json()
        assert data["actions"] == []

    @pytest.mark.asyncio
    async def test_actions_returns_distinct(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """Actions returns sorted distinct action types."""
        response = await authenticated_client.get("/api/audit/actions")
        assert response.status_code == 200
        data = response.json()
        expected_actions = sorted(["create", "update", "delete", "login", "deploy", "scheduled_task"])
        assert data["actions"] == expected_actions


class TestListResourceTypes:
    """Tests for GET /audit/resource-types endpoint."""

    @pytest.mark.asyncio
    async def test_resource_types_requires_auth(self, client: AsyncClient):
        """Resource types endpoint requires authentication."""
        response = await client.get("/api/audit/resource-types")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_resource_types_requires_admin(self, non_admin_client: AsyncClient):
        """Resource types endpoint requires admin role."""
        response = await non_admin_client.get("/api/audit/resource-types")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_resource_types_empty(self, authenticated_client: AsyncClient):
        """Resource types returns empty list when no logs exist."""
        response = await authenticated_client.get("/api/audit/resource-types")
        assert response.status_code == 200
        data = response.json()
        assert data["resource_types"] == []

    @pytest.mark.asyncio
    async def test_resource_types_returns_distinct(
        self, authenticated_client: AsyncClient, sample_audit_logs: list[AuditLog]
    ):
        """Resource types returns sorted distinct types."""
        response = await authenticated_client.get("/api/audit/resource-types")
        assert response.status_code == 200
        data = response.json()
        expected_types = sorted(["rule", "user", "session", "system"])
        assert data["resource_types"] == expected_types
