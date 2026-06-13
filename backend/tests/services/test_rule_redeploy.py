"""Tests for the field-mapping percolator redeploy helper."""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.rule_redeploy import redeploy_rule_to_percolator


def _rule(deployed: bool = True):
    return SimpleNamespace(
        id=uuid.uuid4(),
        deployed_at=datetime.now(UTC) if deployed else None,
        yaml_content="title: t\ndetection:\n  sel:\n    fieldA: x\n  condition: sel\n",
        title="Test Rule",
        severity="high",
    )


def _index_pattern(mode: str = "push"):
    return SimpleNamespace(id=uuid.uuid4(), mode=mode, pattern="logs-*")


@pytest.mark.asyncio
async def test_skips_undeployed_rule():
    out = await redeploy_rule_to_percolator(
        AsyncMock(), MagicMock(), _rule(deployed=False), _index_pattern()
    )
    assert out["status"] == "skipped"
    assert out["reason"] == "not_deployed"


@pytest.mark.asyncio
async def test_skips_pull_mode_rule():
    out = await redeploy_rule_to_percolator(
        AsyncMock(), MagicMock(), _rule(), _index_pattern(mode="pull")
    )
    assert out["status"] == "skipped"
    assert out["reason"] == "pull_mode"


@pytest.mark.asyncio
async def test_redeploys_deployed_push_rule():
    rule = _rule()
    ip = _index_pattern()

    percolator = MagicMock()
    percolator.get_percolator_index_name.return_value = "chad-percolator-logs"

    with (
        patch("app.services.rule_redeploy.sigma_service") as sigma,
        patch("app.services.rule_redeploy.resolve_mappings", new=AsyncMock(return_value={"fieldA": "fieldA.keyword"})),
        patch("app.services.field_type_detector.auto_correct_field_mapping", return_value=("fieldA.keyword", False)),
        patch("app.services.rule_redeploy.PercolatorService", return_value=percolator),
    ):
        sigma.translate_and_validate.return_value = SimpleNamespace(success=True, fields={"fieldA"})
        sigma.translate_with_mappings.return_value = SimpleNamespace(
            success=True, query={"query": {"query_string": {"query": "fieldA.keyword:x"}}}
        )

        out = await redeploy_rule_to_percolator(AsyncMock(), MagicMock(), rule, ip)

    assert out["status"] == "redeployed"
    assert out["percolator_index"] == "chad-percolator-logs"
    # The recompiled inner query (not the outer wrapper) is pushed to the percolator.
    _, kwargs = percolator.deploy_rule.call_args
    assert kwargs["query"] == {"query_string": {"query": "fieldA.keyword:x"}}
    assert kwargs["rule_id"] == str(rule.id)


@pytest.mark.asyncio
async def test_translation_failure_returns_failed():
    with patch("app.services.rule_redeploy.sigma_service") as sigma:
        sigma.translate_and_validate.return_value = SimpleNamespace(success=False, fields=set())
        out = await redeploy_rule_to_percolator(AsyncMock(), MagicMock(), _rule(), _index_pattern())

    assert out["status"] == "failed"
    assert out["reason"] == "validation"
