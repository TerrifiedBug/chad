"""Tests for the shared deployment service (gate flag + apply extraction)."""

import uuid
from unittest.mock import Mock

import pytest

from app.models.notification_settings import NotificationSettings
from app.services.deployment import (
    DeploymentApplyError,
    apply_sigma_rule_deployment,
    is_approval_required,
)


@pytest.mark.asyncio
async def test_is_approval_required_no_settings_row(test_session):
    """Fresh install (no NotificationSettings row) -> gate OFF."""
    assert await is_approval_required(test_session) is False


@pytest.mark.asyncio
async def test_is_approval_required_flag_false(test_session):
    test_session.add(NotificationSettings(require_deploy_approval=False))
    await test_session.commit()
    assert await is_approval_required(test_session) is False


@pytest.mark.asyncio
async def test_is_approval_required_flag_true(test_session):
    test_session.add(NotificationSettings(require_deploy_approval=True))
    await test_session.commit()
    assert await is_approval_required(test_session) is True


@pytest.mark.asyncio
async def test_apply_raises_on_untranslatable_rule(test_session, test_index_pattern, test_user):
    """An un-translatable rule raises DeploymentApplyError(kind='translation')
    before any percolator interaction (os_client never used)."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.rule import Rule, RuleSource, RuleStatus

    rule = Rule(
        id=uuid.uuid4(),
        title="Untranslatable",
        yaml_content="{}",  # no detection / condition -> translation fails
        severity="low",
        status=RuleStatus.UNDEPLOYED,
        source=RuleSource.USER,
        index_pattern_id=test_index_pattern.id,
        created_by=test_user.id,
    )
    test_session.add(rule)
    await test_session.commit()

    res = await test_session.execute(
        select(Rule)
        .where(Rule.id == rule.id)
        .options(selectinload(Rule.index_pattern), selectinload(Rule.versions))
    )
    rule = res.scalar_one()

    os_client = Mock()
    with pytest.raises(DeploymentApplyError) as exc_info:
        await apply_sigma_rule_deployment(
            test_session,
            os_client,
            rule,
            actor_id=test_user.id,
            change_reason="x",
        )
    assert exc_info.value.kind == "translation"
    # os_client must not have been touched on the translation-failure path
    os_client.index.assert_not_called()
