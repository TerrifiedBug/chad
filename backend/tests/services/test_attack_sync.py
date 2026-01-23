# backend/tests/services/test_attack_sync.py
"""Tests for ATT&CK sync service."""
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.rule import Rule, RuleSource, RuleStatus
from app.models.index_pattern import IndexPattern
from app.services.attack_sync import (
    AttackSyncService,
    extract_attack_tags,
    update_rule_attack_mappings,
)


class TestExtractAttackTags:
    """Tests for extract_attack_tags function."""

    def test_extracts_basic_technique_id(self):
        tags = ["attack.t1059", "some.other.tag"]
        result = extract_attack_tags(tags)
        assert result == ["T1059"]

    def test_extracts_subtechnique_id(self):
        tags = ["attack.t1059.001"]
        result = extract_attack_tags(tags)
        assert result == ["T1059.001"]

    def test_extracts_multiple_techniques(self):
        tags = ["attack.t1059", "attack.t1566.001", "attack.t1105"]
        result = extract_attack_tags(tags)
        assert result == ["T1059", "T1566.001", "T1105"]

    def test_case_insensitive(self):
        tags = ["ATTACK.T1059", "Attack.t1566.001"]
        result = extract_attack_tags(tags)
        assert result == ["T1059", "T1566.001"]

    def test_ignores_non_attack_tags(self):
        tags = ["custom.tag", "sigma.logsource", "attack.execution"]
        result = extract_attack_tags(tags)
        assert result == []

    def test_handles_empty_list(self):
        result = extract_attack_tags([])
        assert result == []

    def test_handles_mixed_tags(self):
        tags = [
            "attack.execution",  # Tactic, not technique
            "attack.t1059",  # Valid technique
            "attack.t1059.001",  # Valid sub-technique
            "custom.tag",  # Non-attack
            "attack.persistence",  # Tactic
        ]
        result = extract_attack_tags(tags)
        assert result == ["T1059", "T1059.001"]


class TestUpdateRuleAttackMappings:
    """Tests for update_rule_attack_mappings function."""

    async def _create_test_rule(self, test_session, test_user):
        """Helper to create a test rule with required index pattern and user."""
        # Create index pattern first
        pattern = IndexPattern(
            name="test-attack-pattern",
            pattern="test-attack-*",
            percolator_index="percolator-test-attack",
        )
        test_session.add(pattern)
        await test_session.commit()
        await test_session.refresh(pattern)

        # Create rule
        rule = Rule(
            id=uuid.uuid4(),
            title="Test Rule",
            yaml_content="title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
            source=RuleSource.USER,
            status=RuleStatus.UNDEPLOYED,
            severity="medium",
            index_pattern_id=pattern.id,
            created_by=test_user.id,
        )
        test_session.add(rule)
        await test_session.commit()
        return rule

    @pytest.mark.asyncio
    async def test_creates_mappings_for_existing_techniques(self, test_session, test_user):
        # Create a technique
        technique = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
        )
        test_session.add(technique)
        await test_session.commit()

        # Create a rule
        rule = await self._create_test_rule(test_session, test_user)

        # Update mappings
        tags = ["attack.t1059", "attack.execution"]
        await update_rule_attack_mappings(test_session, str(rule.id), tags)
        await test_session.commit()

        # Verify mapping created
        from sqlalchemy import select

        result = await test_session.execute(
            select(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule.id)
        )
        mappings = result.scalars().all()
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1059"

    @pytest.mark.asyncio
    async def test_skips_non_existing_techniques(self, test_session, test_user):
        # Create a rule (without creating any techniques)
        rule = await self._create_test_rule(test_session, test_user)

        # Update mappings for technique that doesn't exist
        tags = ["attack.t9999"]  # Non-existent
        await update_rule_attack_mappings(test_session, str(rule.id), tags)
        await test_session.commit()

        # Verify no mappings created
        from sqlalchemy import select

        result = await test_session.execute(
            select(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule.id)
        )
        mappings = result.scalars().all()
        assert len(mappings) == 0

    @pytest.mark.asyncio
    async def test_deletes_old_mappings_when_updating(self, test_session, test_user):
        # Create techniques
        technique1 = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
        )
        technique2 = AttackTechnique(
            id="T1566",
            name="Phishing",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            is_subtechnique=False,
        )
        test_session.add_all([technique1, technique2])
        await test_session.commit()

        # Create rule
        rule = await self._create_test_rule(test_session, test_user)

        # Create initial mapping to T1059
        await update_rule_attack_mappings(test_session, str(rule.id), ["attack.t1059"])
        await test_session.commit()

        # Update to different technique
        await update_rule_attack_mappings(test_session, str(rule.id), ["attack.t1566"])
        await test_session.commit()

        # Verify only new mapping exists
        from sqlalchemy import select

        result = await test_session.execute(
            select(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule.id)
        )
        mappings = result.scalars().all()
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1566"

    @pytest.mark.asyncio
    async def test_handles_empty_tags(self, test_session, test_user):
        # Create technique
        technique = AttackTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            is_subtechnique=False,
        )
        test_session.add(technique)
        await test_session.commit()

        # Create rule
        rule = await self._create_test_rule(test_session, test_user)

        await update_rule_attack_mappings(test_session, str(rule.id), ["attack.t1059"])
        await test_session.commit()

        # Update with empty tags
        await update_rule_attack_mappings(test_session, str(rule.id), [])
        await test_session.commit()

        # Verify mappings cleared
        from sqlalchemy import select

        result = await test_session.execute(
            select(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule.id)
        )
        mappings = result.scalars().all()
        assert len(mappings) == 0


class TestAttackSyncService:
    """Tests for AttackSyncService class."""

    def test_tactic_display_names_complete(self):
        """Verify all 14 ATT&CK Enterprise tactics are mapped."""
        service = AttackSyncService()
        expected_tactics = [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]
        for tactic in expected_tactics:
            assert tactic in service.TACTIC_DISPLAY_NAMES

    @pytest.mark.asyncio
    async def test_sync_returns_error_on_network_failure(self, test_session):
        """Test sync handles network errors gracefully."""
        service = AttackSyncService()

        with patch("app.services.attack_sync.MitreAttackData") as mock_mitre:
            mock_mitre.side_effect = Exception("Network error")

            result = await service.sync(test_session)

            assert result.success is False
            assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_sync_processes_techniques(self, test_session):
        """Test sync properly processes ATT&CK data."""
        service = AttackSyncService()

        # Mock MitreAttackData
        with patch("app.services.attack_sync.MitreAttackData") as mock_mitre:
            mock_attack_data = MagicMock()

            # Mock technique data
            mock_technique = {
                "name": "Command and Scripting Interpreter",
                "description": "Test description",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Process: Process Creation"],
            }

            # Mock tactic data
            mock_tactic = {
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"}
                ],
            }

            mock_attack_data.get_techniques.return_value = [mock_technique]
            mock_attack_data.get_tactics.return_value = [mock_tactic]
            mock_mitre.return_value = mock_attack_data

            result = await service.sync(test_session)

            assert result.success is True
            assert result.techniques_updated > 0

            # Verify technique was stored
            from sqlalchemy import select

            db_result = await test_session.execute(
                select(AttackTechnique).where(AttackTechnique.id == "T1059")
            )
            technique = db_result.scalar_one_or_none()
            assert technique is not None
            assert technique.name == "Command and Scripting Interpreter"
            assert technique.tactic_id == "TA0002"
            assert technique.tactic_name == "Execution"

    @pytest.mark.asyncio
    async def test_sync_skips_revoked_techniques(self, test_session):
        """Test sync skips revoked techniques."""
        service = AttackSyncService()

        with patch("app.services.attack_sync.MitreAttackData") as mock_mitre:
            mock_attack_data = MagicMock()

            # Revoked technique
            mock_technique = {
                "name": "Revoked Technique",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0001"}
                ],
            }

            mock_attack_data.get_techniques.return_value = [mock_technique]
            mock_attack_data.get_tactics.return_value = []
            mock_mitre.return_value = mock_attack_data

            result = await service.sync(test_session)

            assert result.success is True

            # Verify technique was NOT stored
            from sqlalchemy import select

            db_result = await test_session.execute(
                select(AttackTechnique).where(AttackTechnique.id == "T0001")
            )
            technique = db_result.scalar_one_or_none()
            assert technique is None

    @pytest.mark.asyncio
    async def test_sync_handles_subtechniques(self, test_session):
        """Test sync properly handles sub-techniques."""
        service = AttackSyncService()

        with patch("app.services.attack_sync.MitreAttackData") as mock_mitre:
            mock_attack_data = MagicMock()

            # Sub-technique
            mock_technique = {
                "name": "PowerShell",
                "description": "PowerShell sub-technique",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
            }

            mock_tactic = {
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"}
                ],
            }

            mock_attack_data.get_techniques.return_value = [mock_technique]
            mock_attack_data.get_tactics.return_value = [mock_tactic]
            mock_mitre.return_value = mock_attack_data

            result = await service.sync(test_session)

            assert result.success is True

            # Verify sub-technique was stored correctly
            from sqlalchemy import select

            db_result = await test_session.execute(
                select(AttackTechnique).where(AttackTechnique.id == "T1059.001")
            )
            technique = db_result.scalar_one_or_none()
            assert technique is not None
            assert technique.is_subtechnique is True
            assert technique.parent_id == "T1059"
