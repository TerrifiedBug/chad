"""Tests for the DeploymentRequest / DeploymentRequestItem models."""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.deployment_request import (
    DeploymentRequest,
    DeploymentRequestItem,
    DeploymentRequestKind,
    DeploymentRequestStatus,
)


async def _load_with_items(session, request_id):
    res = await session.execute(
        select(DeploymentRequest)
        .where(DeploymentRequest.id == request_id)
        .options(selectinload(DeploymentRequest.items))
    )
    return res.scalar_one()


@pytest.mark.asyncio
async def test_create_deployment_request_with_items(test_session, test_user, test_rule):
    """A new request defaults to PENDING and carries its pinned items."""
    req = DeploymentRequest(
        requested_by=test_user.id,
        change_reason="ship it",
    )
    req.items.append(
        DeploymentRequestItem(
            rule_id=test_rule.id,
            version_number=1,
            kind=DeploymentRequestKind.SIGMA.value,
        )
    )
    test_session.add(req)
    await test_session.commit()

    loaded = await _load_with_items(test_session, req.id)

    assert loaded.id is not None
    assert loaded.status == DeploymentRequestStatus.PENDING.value
    assert loaded.reviewed_by is None
    assert loaded.reviewed_at is None
    assert loaded.applied_at is None
    assert loaded.target_environment_id is None  # inert seam
    assert len(loaded.items) == 1
    assert loaded.items[0].rule_id == test_rule.id
    assert loaded.items[0].version_number == 1
    assert loaded.items[0].apply_status is None


@pytest.mark.asyncio
async def test_items_cascade_delete_with_request(test_session, test_user, test_rule):
    """Deleting a request removes its items (cascade)."""
    req = DeploymentRequest(requested_by=test_user.id, change_reason="x")
    item = DeploymentRequestItem(rule_id=test_rule.id, version_number=1)
    req.items.append(item)
    test_session.add(req)
    await test_session.commit()
    item_id = item.id

    await test_session.delete(req)
    await test_session.commit()

    res = await test_session.execute(
        select(DeploymentRequestItem).where(DeploymentRequestItem.id == item_id)
    )
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_correlation_item_uses_correlation_fk(test_session, test_user, correlation_rule):
    """A correlation item pins via correlation_rule_id, leaving rule_id null."""
    req = DeploymentRequest(requested_by=test_user.id, change_reason="corr")
    req.items.append(
        DeploymentRequestItem(
            correlation_rule_id=correlation_rule.id,
            version_number=1,
            kind=DeploymentRequestKind.CORRELATION.value,
        )
    )
    test_session.add(req)
    await test_session.commit()

    loaded = await _load_with_items(test_session, req.id)

    assert loaded.items[0].rule_id is None
    assert loaded.items[0].correlation_rule_id == correlation_rule.id
    assert loaded.items[0].kind == DeploymentRequestKind.CORRELATION.value
