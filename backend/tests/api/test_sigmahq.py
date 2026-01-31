# backend/tests/api/test_sigmahq.py
"""Tests for the SigmaHQ API endpoints."""

import uuid
from dataclasses import dataclass

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, MagicMock, AsyncMock, call

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.index_pattern import IndexPattern
from app.models.user import User, UserRole


@dataclass
class MockSyncResult:
    """Mock sync result object."""
    success: bool
    message: str
    commit_hash: str | None = None
    rule_counts: dict | None = None
    rule_count: int | None = None
    error: str | None = None
    new_rules: int = 0


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
async def non_admin_client(
    test_session: AsyncSession, non_admin_token: str
):
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
async def test_index_pattern(test_session: AsyncSession) -> IndexPattern:
    """Create a test index pattern."""
    index_pattern = IndexPattern(
        id=uuid.uuid4(),
        name="Test Pattern",
        pattern="logs-*",
        percolator_index=".percolator-logs",
        description="Test index pattern for testing",
    )
    test_session.add(index_pattern)
    await test_session.commit()
    await test_session.refresh(index_pattern)
    return index_pattern


class TestSigmaHQStatus:
    """Tests for GET /sigmahq/status endpoint."""

    @pytest.mark.asyncio
    async def test_get_status_requires_auth(self, client: AsyncClient):
        """Status endpoint requires authentication."""
        response = await client.get("/api/sigmahq/status")
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_status_not_cloned(self, authenticated_client: AsyncClient):
        """Status returns cloned=False when repo is not cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = False

            response = await authenticated_client.get("/api/sigmahq/status")

            assert response.status_code == 200
            data = response.json()
            assert data["cloned"] is False
            assert data["commit_hash"] is None
            assert data["rule_counts"] is None

    @pytest.mark.asyncio
    async def test_get_status_cloned(self, authenticated_client: AsyncClient):
        """Status returns repo info when cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_current_commit_hash.return_value = "abc123def456"
            mock_service.count_rules_all.return_value = {
                "detection": 2500,
                "threat_hunting": 100,
                "emerging_threats": 50,
            }
            mock_service.DEFAULT_REPO_URL = "https://github.com/SigmaHQ/sigma.git"

            response = await authenticated_client.get("/api/sigmahq/status")

            assert response.status_code == 200
            data = response.json()
            assert data["cloned"] is True
            assert data["commit_hash"] == "abc123def456"
            assert data["rule_counts"]["detection"] == 2500
            assert data["rule_counts"]["threat_hunting"] == 100
            assert data["rule_counts"]["emerging_threats"] == 50
            assert data["repo_url"] == "https://github.com/SigmaHQ/sigma.git"


class TestSigmaHQSync:
    """Tests for POST /sigmahq/sync endpoint."""

    @pytest.mark.asyncio
    async def test_sync_requires_auth(self, client: AsyncClient):
        """Sync endpoint requires authentication."""
        response = await client.post("/api/sigmahq/sync", json={})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_sync_requires_admin(self, non_admin_client: AsyncClient):
        """Sync endpoint requires admin role."""
        response = await non_admin_client.post("/api/sigmahq/sync", json={})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_sync_triggers_clone_when_not_cloned(self, authenticated_client: AsyncClient):
        """Sync clones repo when not already cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service, \
             patch("app.api.sigmahq.send_system_notification"), \
             patch("app.api.sigmahq.audit_log"):
            mock_service.is_repo_cloned.return_value = False
            mock_service.clone_repo.return_value = MockSyncResult(
                success=True,
                message="Repository cloned successfully",
                commit_hash="abc123",
                rule_counts={"detection": 2500, "threat_hunting": 100, "emerging_threats": 50},
                rule_count=2650,
            )

            response = await authenticated_client.post("/api/sigmahq/sync", json={})

            assert response.status_code == 200
            mock_service.clone_repo.assert_called_once()
            data = response.json()
            assert data["success"] is True
            assert data["commit_hash"] == "abc123"
            assert data["rule_counts"]["detection"] == 2500

    @pytest.mark.asyncio
    async def test_sync_triggers_pull_when_cloned(self, authenticated_client: AsyncClient):
        """Sync pulls when repo is already cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service, \
             patch("app.api.sigmahq.send_system_notification"), \
             patch("app.api.sigmahq.audit_log"):
            mock_service.is_repo_cloned.return_value = True
            mock_service.pull_repo.return_value = MockSyncResult(
                success=True,
                message="Repository updated successfully",
                commit_hash="def456",
                rule_counts={"detection": 2600, "threat_hunting": 105, "emerging_threats": 52},
                rule_count=2757,
            )

            response = await authenticated_client.post("/api/sigmahq/sync", json={})

            assert response.status_code == 200
            mock_service.pull_repo.assert_called_once()
            mock_service.clone_repo.assert_not_called()
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_sync_sends_notifications_on_success(self, authenticated_client: AsyncClient):
        """Sync sends notifications on successful sync."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service, \
             patch("app.api.sigmahq.send_system_notification") as mock_notify, \
             patch("app.api.sigmahq.audit_log") as mock_audit:
            mock_service.is_repo_cloned.return_value = True
            mock_service.pull_repo.return_value = MockSyncResult(
                success=True,
                message="Repository updated successfully",
                commit_hash="def456",
                rule_count=2652,
                rule_counts={"detection": 2600, "threat_hunting": 105, "emerging_threats": 52},
                new_rules=10,
            )
            mock_audit.return_value = MagicMock()

            response = await authenticated_client.post("/api/sigmahq/sync", json={})

            assert response.status_code == 200
            # Verify audit log was called
            mock_audit.assert_called_once()
            # Verify sync_complete notification was sent
            assert mock_notify.call_count >= 1
            call_args = mock_notify.call_args_list
            # Check for sync_complete notification
            sync_complete_calls = [c for c in call_args if "sigmahq_sync_complete" in str(c)]
            assert len(sync_complete_calls) > 0, "sync_complete notification should be sent"

    @pytest.mark.asyncio
    async def test_sync_sends_new_rules_notification(self, authenticated_client: AsyncClient):
        """Sync sends new rules notification when new rules are available."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service, \
             patch("app.api.sigmahq.send_system_notification") as mock_notify, \
             patch("app.api.sigmahq.audit_log") as mock_audit:
            mock_service.is_repo_cloned.return_value = True
            mock_service.pull_repo.return_value = MockSyncResult(
                success=True,
                message="Repository updated with new rules",
                commit_hash="xyz789",
                rule_count=2700,
                rule_counts={"detection": 2650, "threat_hunting": 110, "emerging_threats": 55},
                new_rules=48,
            )
            mock_audit.return_value = MagicMock()

            response = await authenticated_client.post("/api/sigmahq/sync", json={})

            assert response.status_code == 200
            # Verify new_rules notification was sent
            call_args = mock_notify.call_args_list
            new_rules_calls = [c for c in call_args if "sigmahq_new_rules" in str(c)]
            assert len(new_rules_calls) > 0, "new_rules notification should be sent when new rules exist"

    @pytest.mark.asyncio
    async def test_sync_sends_failure_notification_on_error(self, authenticated_client: AsyncClient):
        """Sync sends failure notification when sync fails."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service, \
             patch("app.api.sigmahq.send_system_notification") as mock_notify, \
             patch("app.api.sigmahq.audit_log") as mock_audit:
            mock_service.is_repo_cloned.return_value = True
            mock_service.pull_repo.return_value = MockSyncResult(
                success=False,
                message="Sync failed",
                error="Network error",
                rule_count=None,
            )
            mock_audit.return_value = MagicMock()

            response = await authenticated_client.post("/api/sigmahq/sync", json={})

            assert response.status_code == 200  # Endpoint still returns 200
            data = response.json()
            assert data["success"] is False
            # Verify sync_failed notification was sent
            call_args = mock_notify.call_args_list
            failed_calls = [c for c in call_args if "sync_failed" in str(c)]
            assert len(failed_calls) > 0, "sync_failed notification should be sent on error"


class TestSigmaHQRules:
    """Tests for SigmaHQ rules browsing endpoints."""

    @pytest.mark.asyncio
    async def test_get_category_tree_requires_auth(self, client: AsyncClient):
        """Category tree endpoint requires authentication."""
        response = await client.get("/api/sigmahq/rules")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_category_tree_not_cloned(self, authenticated_client: AsyncClient):
        """Category tree returns error when repo not cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = False

            response = await authenticated_client.get("/api/sigmahq/rules")

            assert response.status_code == 400
            assert "not cloned" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_category_tree(self, authenticated_client: AsyncClient):
        """Category tree returns category structure."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_category_tree.return_value = {
                "windows": {"count": 100, "children": {"process_creation": {"count": 50, "children": {}}}},
                "linux": {"count": 30, "children": {}},
            }

            response = await authenticated_client.get("/api/sigmahq/rules")

            assert response.status_code == 200
            data = response.json()
            assert "categories" in data
            assert "windows" in data["categories"]
            assert data["categories"]["windows"]["count"] == 100

    @pytest.mark.asyncio
    async def test_get_rule_content(self, authenticated_client: AsyncClient):
        """Get rule content returns YAML and metadata."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_rule_content.return_value = "title: Test Rule\nlevel: high\n"

            response = await authenticated_client.get("/api/sigmahq/rules/windows/test.yml")

            assert response.status_code == 200
            data = response.json()
            assert data["content"] == "title: Test Rule\nlevel: high\n"
            assert data["path"] == "windows/test.yml"
            assert data["metadata"]["title"] == "Test Rule"
            assert data["metadata"]["level"] == "high"

    @pytest.mark.asyncio
    async def test_get_rule_content_not_found(self, authenticated_client: AsyncClient):
        """Get rule content returns 404 when rule not found."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_rule_content.return_value = None

            response = await authenticated_client.get("/api/sigmahq/rules/windows/nonexistent.yml")

            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_list_rules_in_category(self, authenticated_client: AsyncClient):
        """List rules in category returns rule list."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.list_rules_in_category.return_value = [
                {
                    "title": "Test Rule 1",
                    "status": "stable",
                    "severity": "high",
                    "description": "A test rule",
                    "tags": ["attack.execution"],
                    "path": "windows/process_creation/test1.yml",
                    "filename": "test1.yml",
                },
            ]

            response = await authenticated_client.get("/api/sigmahq/rules/list/windows/process_creation")

            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert len(data["rules"]) == 1
            assert data["rules"][0]["title"] == "Test Rule 1"


class TestSigmaHQSearch:
    """Tests for POST /sigmahq/search endpoint."""

    @pytest.mark.asyncio
    async def test_search_rules(self, authenticated_client: AsyncClient):
        """Search rules returns matching results."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.search_rules.return_value = [
                {
                    "title": "Mimikatz",
                    "status": "stable",
                    "severity": "critical",
                    "description": "Detects Mimikatz",
                    "tags": ["attack.credential_access"],
                    "path": "windows/process_creation/mimikatz.yml",
                    "filename": "mimikatz.yml",
                },
            ]

            response = await authenticated_client.post(
                "/api/sigmahq/search",
                json={"query": "mimikatz", "limit": 10},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert data["rules"][0]["title"] == "Mimikatz"
            # search_rules is now called with an additional rule_type parameter
            mock_service.search_rules.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_not_cloned(self, authenticated_client: AsyncClient):
        """Search returns error when repo not cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = False

            response = await authenticated_client.post(
                "/api/sigmahq/search",
                json={"query": "test"},
            )

            assert response.status_code == 400


class TestSigmaHQImport:
    """Tests for POST /sigmahq/import endpoint."""

    # Use a valid UUID for index_pattern_id in tests
    TEST_INDEX_PATTERN_ID = "12345678-1234-1234-1234-123456789012"

    @pytest.mark.asyncio
    async def test_import_requires_auth(self, client: AsyncClient):
        """Import endpoint requires authentication."""
        response = await client.post(
            "/api/sigmahq/import",
            json={"rule_path": "windows/test.yml", "index_pattern_id": self.TEST_INDEX_PATTERN_ID},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_import_returns_400_when_not_cloned(self, authenticated_client: AsyncClient):
        """Import returns 400 if SigmaHQ repo is not cloned."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = False

            response = await authenticated_client.post(
                "/api/sigmahq/import",
                json={"rule_path": "windows/test.yml", "index_pattern_id": self.TEST_INDEX_PATTERN_ID},
            )

            assert response.status_code == 400
            assert "not cloned" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_import_returns_404_when_rule_not_found(self, authenticated_client: AsyncClient):
        """Import returns 404 if the rule doesn't exist in SigmaHQ repo."""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_rule_content.return_value = None

            response = await authenticated_client.post(
                "/api/sigmahq/import",
                json={"rule_path": "windows/nonexistent.yml", "index_pattern_id": self.TEST_INDEX_PATTERN_ID},
            )

            assert response.status_code == 404
            assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_import_success(self, authenticated_client: AsyncClient, test_index_pattern: IndexPattern):
        """Successful import creates disabled rule with version."""
        rule_yaml = """title: Test Detection Rule
description: Detects test activity
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    condition: selection
"""
        with patch("app.api.sigmahq.sigmahq_service") as mock_service:
            mock_service.is_repo_cloned.return_value = True
            mock_service.get_rule_content.return_value = rule_yaml

            response = await authenticated_client.post(
                "/api/sigmahq/import",
                json={"rule_path": "windows/test_rule.yml", "index_pattern_id": str(test_index_pattern.id)},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["title"] == "Test Detection Rule"
            assert "rule_id" in data
            assert data["message"] == "Rule imported successfully. Review and deploy when ready."
