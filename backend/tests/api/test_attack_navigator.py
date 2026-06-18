"""Tests for the MITRE ATT&CK Navigator layer JSON export endpoint."""
import uuid

import pytest
from httpx import AsyncClient

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.index_pattern import IndexPattern
from app.models.rule import Rule, RuleSource, RuleStatus


class TestNavigatorExport:
    @pytest.mark.asyncio
    async def test_requires_auth(self, client: AsyncClient):
        response = await client.post(
            "/api/reports/attack-coverage/navigator", json={}
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_returns_navigator_layer_schema(
        self, authenticated_client: AsyncClient, test_session
    ):
        tech = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
            data_sources=["Process: Process Creation"],
        )
        test_session.add(tech)
        await test_session.commit()

        response = await authenticated_client.post(
            "/api/reports/attack-coverage/navigator", json={}
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        layer = response.json()
        # Core Navigator layer fields
        assert layer["domain"] == "enterprise-attack"
        assert "versions" in layer
        assert layer["versions"]["layer"] == "4.5"
        assert isinstance(layer["techniques"], list)
        assert isinstance(layer["legendItems"], list)
        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
        assert "color" in entry
        assert "score" in entry
        assert "comment" in entry

    @pytest.mark.asyncio
    async def test_covered_technique_has_covered_legend_color(
        self, authenticated_client: AsyncClient, test_session, test_user
    ):
        tech = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
            data_sources=["Process: Process Creation"],
        )
        test_session.add(tech)
        await test_session.commit()

        ip = IndexPattern(
            id=uuid.uuid4(),
            name="nav-logs",
            pattern="nav-logs-*",
            percolator_index="perc-nav-logs",
        )
        test_session.add(ip)
        await test_session.commit()

        rule = Rule(
            id=uuid.uuid4(),
            title="PS",
            yaml_content="title: t\nlogsource:\n  product: windows\ndetection:\n  s:\n    EventID: 1\n  condition: s",  # noqa: E501
            severity="high",
            status=RuleStatus.DEPLOYED,
            source=RuleSource.USER,
            index_pattern_id=ip.id,
            created_by=test_user.id,
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)
        test_session.add(RuleAttackMapping(rule_id=rule.id, technique_id="T1059"))
        await test_session.commit()

        # telemetry=False -> rule-only grading -> deployed rule == covered
        response = await authenticated_client.post(
            "/api/reports/attack-coverage/navigator",
            json={"telemetry": False},
        )
        assert response.status_code == 200
        layer = response.json()
        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
        assert entry["color"] == "#2e7d32"  # covered green
        assert entry["score"] == 100
