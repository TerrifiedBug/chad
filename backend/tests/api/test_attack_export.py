"""Tests for the ATT&CK coverage PDF export endpoint."""

import uuid

import pytest
from httpx import AsyncClient

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus


class TestAttackCoverageExport:
    """Tests for POST /reports/attack-coverage endpoint."""

    @pytest.mark.asyncio
    async def test_export_attack_coverage_pdf(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test exporting ATT&CK coverage as PDF."""
        response = await authenticated_client.post(
            "/api/reports/attack-coverage",
            json={"format": "pdf"},
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        # Check for PDF magic bytes
        assert response.content[:4] == b"%PDF"

    @pytest.mark.asyncio
    async def test_export_attack_coverage_requires_auth(self, client: AsyncClient):
        """Test that export endpoint requires authentication."""
        response = await client.post(
            "/api/reports/attack-coverage",
            json={"format": "pdf"},
        )
        # HTTPBearer returns 403 when no credentials provided
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_export_attack_coverage_with_data(
        self, authenticated_client: AsyncClient, test_session, test_user
    ):
        """Test PDF export with actual techniques and rules."""
        # Create test techniques
        technique1 = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
            platforms=["Windows", "Linux", "macOS"],
        )
        technique2 = AttackTechnique(
            id="T1055",
            name="Process Injection",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            is_subtechnique=False,
            platforms=["Windows", "Linux"],
        )
        technique3 = AttackTechnique(
            id="T1003",
            name="OS Credential Dumping",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            is_subtechnique=False,
            platforms=["Windows"],
        )
        test_session.add_all([technique1, technique2, technique3])
        await test_session.commit()

        # Create an index pattern
        index_pattern = IndexPattern(
            id=uuid.uuid4(),
            name="logs-*",
            pattern="logs-*",
            percolator_index="percolator-logs",
        )
        test_session.add(index_pattern)
        await test_session.commit()

        # Create a rule mapped to T1059
        rule = Rule(
            id=uuid.uuid4(),
            title="PowerShell Execution",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel",
            severity="high",
            status=RuleStatus.DEPLOYED,
            source=RuleSource.USER,
            index_pattern_id=index_pattern.id,
            created_by=test_user.id,
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        # Create the mapping
        mapping = RuleAttackMapping(
            rule_id=rule.id,
            technique_id="T1059",
        )
        test_session.add(mapping)
        await test_session.commit()

        # Generate the export
        response = await authenticated_client.post(
            "/api/reports/attack-coverage",
            json={"format": "pdf"},
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content[:4] == b"%PDF"
        # PDF should have some content
        assert len(response.content) > 1000

    @pytest.mark.asyncio
    async def test_export_attack_coverage_content_disposition(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that export has correct filename in Content-Disposition header."""
        response = await authenticated_client.post(
            "/api/reports/attack-coverage",
            json={"format": "pdf"},
        )
        assert response.status_code == 200
        content_disposition = response.headers.get("content-disposition", "")
        assert "attachment" in content_disposition
        assert "attack-coverage-" in content_disposition
        assert ".pdf" in content_disposition

    @pytest.mark.asyncio
    async def test_export_attack_coverage_default_format(
        self, authenticated_client: AsyncClient, test_session
    ):
        """Test that default format is PDF when not specified."""
        response = await authenticated_client.post(
            "/api/reports/attack-coverage",
            json={},
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
