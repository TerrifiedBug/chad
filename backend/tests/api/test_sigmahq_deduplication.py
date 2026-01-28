import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, MagicMock

from app.main import app
from app.models.index_pattern import IndexPattern
from app.models.user import User


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


class TestSigmaHQDeduplication:
    """Tests for SigmaHQ import deduplication."""

    @pytest.mark.asyncio
    async def test_import_duplicate_rule_fails(
        self,
        client: AsyncClient,
        test_user: User,
        test_index_pattern: IndexPattern
    ):
        """Test that importing the same SigmaHQ rule twice returns 409 Conflict."""
        # Mock the SigmaHQ service
        mock_rule_content = """
        title: Test Rule
        description: Test description
        level: medium
        tags: []
        """
        mock_service = MagicMock()
        mock_service.is_repo_cloned.return_value = True
        mock_service.get_rule_content.return_value = mock_rule_content

        with patch('app.api.sigmahq.sigmahq_service', mock_service):
            # First import should succeed
            response1 = await client.post("/api/sigmahq/import", json={
                "rule_path": "test/rule.yml",
                "index_pattern_id": str(test_index_pattern.id),
                "rule_type": "detection"
            })
            assert response1.status_code == 201

            # Second import should fail with 409
            response2 = await client.post("/api/sigmahq/import", json={
                "rule_path": "test/rule.yml",
                "index_pattern_id": str(test_index_pattern.id),
                "rule_type": "detection"
            })
            assert response2.status_code == 409
            assert "rule_already_imported" in response2.json()["detail"]["error"]
