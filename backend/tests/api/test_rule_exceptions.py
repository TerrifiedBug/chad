# backend/tests/api/test_rule_exceptions.py
"""Tests for rule exception API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleStatus
from app.models.rule_exception import RuleException, ExceptionOperator
from app.models.user import User, UserRole


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


@pytest_asyncio.fixture(scope="function")
async def test_rule(
    test_session: AsyncSession, test_index_pattern: IndexPattern, test_user: User
) -> Rule:
    """Create a test rule."""
    rule = Rule(
        id=uuid.uuid4(),
        title="Test Rule",
        description="A test rule for exception testing",
        yaml_content="""title: Test Rule
level: high
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
""",
        severity="high",
        status=RuleStatus.ENABLED,
        index_pattern_id=test_index_pattern.id,
        created_by=test_user.id,
    )
    test_session.add(rule)
    await test_session.commit()
    await test_session.refresh(rule)
    return rule


@pytest_asyncio.fixture(scope="function")
async def test_exception(
    test_session: AsyncSession, test_rule: Rule, test_user: User
) -> RuleException:
    """Create a test exception."""
    exception = RuleException(
        id=uuid.uuid4(),
        rule_id=test_rule.id,
        field="source.ip",
        operator=ExceptionOperator.EQUALS,
        value="192.168.1.100",
        reason="Authorized scanner",
        created_by=test_user.id,
    )
    test_session.add(exception)
    await test_session.commit()
    await test_session.refresh(exception)
    return exception


class TestListRuleExceptions:
    """Tests for GET /rules/{rule_id}/exceptions endpoint."""

    @pytest.mark.asyncio
    async def test_list_exceptions_requires_auth(
        self, client: AsyncClient, test_rule: Rule
    ):
        """List exceptions endpoint requires authentication."""
        response = await client.get(f"/api/rules/{test_rule.id}/exceptions")
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_exceptions_empty(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """List exceptions returns empty list when no exceptions exist."""
        response = await authenticated_client.get(
            f"/api/rules/{test_rule.id}/exceptions"
        )
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_list_exceptions_with_data(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """List exceptions returns all exceptions for a rule."""
        response = await authenticated_client.get(
            f"/api/rules/{test_rule.id}/exceptions"
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(test_exception.id)
        assert data[0]["field"] == "source.ip"
        assert data[0]["operator"] == "equals"
        assert data[0]["value"] == "192.168.1.100"
        assert data[0]["reason"] == "Authorized scanner"
        assert data[0]["is_active"] is True

    @pytest.mark.asyncio
    async def test_list_exceptions_rule_not_found(
        self, authenticated_client: AsyncClient
    ):
        """List exceptions returns 404 for non-existent rule."""
        fake_uuid = uuid.uuid4()
        response = await authenticated_client.get(f"/api/rules/{fake_uuid}/exceptions")
        assert response.status_code == 404
        assert "Rule not found" in response.json()["detail"]


class TestCreateRuleException:
    """Tests for POST /rules/{rule_id}/exceptions endpoint."""

    @pytest.mark.asyncio
    async def test_create_exception_requires_auth(
        self, client: AsyncClient, test_rule: Rule
    ):
        """Create exception endpoint requires authentication."""
        response = await client.post(
            f"/api/rules/{test_rule.id}/exceptions",
            json={
                "field": "user.name",
                "operator": "equals",
                "value": "admin",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_create_exception_success(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """Create exception successfully creates a new exception."""
        response = await authenticated_client.post(
            f"/api/rules/{test_rule.id}/exceptions",
            json={
                "field": "user.name",
                "operator": "equals",
                "value": "admin",
                "reason": "Admin user is allowed",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["field"] == "user.name"
        assert data["operator"] == "equals"
        assert data["value"] == "admin"
        assert data["reason"] == "Admin user is allowed"
        assert data["is_active"] is True
        assert data["rule_id"] == str(test_rule.id)
        assert "id" in data
        assert "created_at" in data

    @pytest.mark.asyncio
    async def test_create_exception_with_different_operators(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """Create exception with different operators."""
        operators = ["equals", "not_equals", "contains", "starts_with", "regex"]
        for operator in operators:
            response = await authenticated_client.post(
                f"/api/rules/{test_rule.id}/exceptions",
                json={
                    "field": f"field_{operator}",
                    "operator": operator,
                    "value": "test_value",
                },
            )
            assert response.status_code == 201
            assert response.json()["operator"] == operator

    @pytest.mark.asyncio
    async def test_create_exception_rule_not_found(
        self, authenticated_client: AsyncClient
    ):
        """Create exception returns 404 for non-existent rule."""
        fake_uuid = uuid.uuid4()
        response = await authenticated_client.post(
            f"/api/rules/{fake_uuid}/exceptions",
            json={
                "field": "user.name",
                "operator": "equals",
                "value": "admin",
            },
        )
        assert response.status_code == 404
        assert "Rule not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_exception_default_operator(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """Create exception uses default operator when not specified."""
        response = await authenticated_client.post(
            f"/api/rules/{test_rule.id}/exceptions",
            json={
                "field": "user.name",
                "value": "admin",
            },
        )
        assert response.status_code == 201
        assert response.json()["operator"] == "equals"


class TestUpdateRuleException:
    """Tests for PATCH /rules/{rule_id}/exceptions/{exception_id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_exception_requires_auth(
        self, client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception endpoint requires authentication."""
        response = await client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"is_active": False},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_exception_toggle_active(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can toggle active state."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False

        # Toggle back
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"is_active": True},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is True

    @pytest.mark.asyncio
    async def test_update_exception_change_field(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can change field name."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"field": "destination.ip"},
        )
        assert response.status_code == 200
        assert response.json()["field"] == "destination.ip"

    @pytest.mark.asyncio
    async def test_update_exception_change_operator(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can change operator."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"operator": "contains"},
        )
        assert response.status_code == 200
        assert response.json()["operator"] == "contains"

    @pytest.mark.asyncio
    async def test_update_exception_change_value(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can change value."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"value": "10.0.0.1"},
        )
        assert response.status_code == 200
        assert response.json()["value"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_update_exception_change_reason(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can change reason."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={"reason": "Updated reason"},
        )
        assert response.status_code == 200
        assert response.json()["reason"] == "Updated reason"

    @pytest.mark.asyncio
    async def test_update_exception_multiple_fields(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Update exception can change multiple fields at once."""
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}",
            json={
                "field": "new.field",
                "operator": "regex",
                "value": ".*test.*",
                "reason": "New reason",
                "is_active": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["field"] == "new.field"
        assert data["operator"] == "regex"
        assert data["value"] == ".*test.*"
        assert data["reason"] == "New reason"
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_exception_not_found(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """Update exception returns 404 for non-existent exception."""
        fake_uuid = uuid.uuid4()
        response = await authenticated_client.patch(
            f"/api/rules/{test_rule.id}/exceptions/{fake_uuid}",
            json={"is_active": False},
        )
        assert response.status_code == 404
        assert "Exception not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_exception_wrong_rule(
        self,
        authenticated_client: AsyncClient,
        test_session: AsyncSession,
        test_index_pattern: IndexPattern,
        test_user: User,
        test_exception: RuleException,
    ):
        """Update exception returns 404 when exception belongs to different rule."""
        # Create another rule
        other_rule = Rule(
            id=uuid.uuid4(),
            title="Other Rule",
            description="Another test rule",
            yaml_content="title: Other\nlevel: low\n",
            severity="low",
            status=RuleStatus.ENABLED,
            index_pattern_id=test_index_pattern.id,
            created_by=test_user.id,
        )
        test_session.add(other_rule)
        await test_session.commit()

        # Try to update exception using wrong rule ID
        response = await authenticated_client.patch(
            f"/api/rules/{other_rule.id}/exceptions/{test_exception.id}",
            json={"is_active": False},
        )
        assert response.status_code == 404
        assert "Exception not found" in response.json()["detail"]


class TestDeleteRuleException:
    """Tests for DELETE /rules/{rule_id}/exceptions/{exception_id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_exception_requires_auth(
        self, client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Delete exception endpoint requires authentication."""
        response = await client.delete(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}"
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_exception_success(
        self, authenticated_client: AsyncClient, test_rule: Rule, test_exception: RuleException
    ):
        """Delete exception successfully removes the exception."""
        response = await authenticated_client.delete(
            f"/api/rules/{test_rule.id}/exceptions/{test_exception.id}"
        )
        assert response.status_code == 204

        # Verify it's gone
        response = await authenticated_client.get(
            f"/api/rules/{test_rule.id}/exceptions"
        )
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_delete_exception_not_found(
        self, authenticated_client: AsyncClient, test_rule: Rule
    ):
        """Delete exception returns 404 for non-existent exception."""
        fake_uuid = uuid.uuid4()
        response = await authenticated_client.delete(
            f"/api/rules/{test_rule.id}/exceptions/{fake_uuid}"
        )
        assert response.status_code == 404
        assert "Exception not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_delete_exception_wrong_rule(
        self,
        authenticated_client: AsyncClient,
        test_session: AsyncSession,
        test_index_pattern: IndexPattern,
        test_user: User,
        test_exception: RuleException,
    ):
        """Delete exception returns 404 when exception belongs to different rule."""
        # Create another rule
        other_rule = Rule(
            id=uuid.uuid4(),
            title="Other Rule",
            description="Another test rule",
            yaml_content="title: Other\nlevel: low\n",
            severity="low",
            status=RuleStatus.ENABLED,
            index_pattern_id=test_index_pattern.id,
            created_by=test_user.id,
        )
        test_session.add(other_rule)
        await test_session.commit()

        # Try to delete exception using wrong rule ID
        response = await authenticated_client.delete(
            f"/api/rules/{other_rule.id}/exceptions/{test_exception.id}"
        )
        assert response.status_code == 404
        assert "Exception not found" in response.json()["detail"]
