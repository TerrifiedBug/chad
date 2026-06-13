"""Regression tests for alert ID validation.

CHAD alert IDs are 32-char hex digests (generate_deterministic_alert_id), not
UUIDs. The bulk endpoints previously validated them with UUID(), rejecting every
real alert ID and breaking bulk status updates and bulk delete.
"""

import pytest
from pydantic import ValidationError

from app.api.alerts import BulkAlertDelete, BulkAlertStatusUpdate
from app.services.alerts import generate_deterministic_alert_id


def test_bulk_delete_accepts_real_alert_id():
    real_id = generate_deterministic_alert_id("rule-1", {"message": "x"})
    assert len(real_id) == 32  # sha256[:32]
    model = BulkAlertDelete(alert_ids=[real_id])
    assert model.alert_ids == [real_id]


def test_bulk_status_accepts_real_alert_id():
    real_id = generate_deterministic_alert_id("rule-1", {"message": "x"})
    model = BulkAlertStatusUpdate(alert_ids=[real_id], status="resolved")
    assert model.alert_ids == [real_id]


def test_bulk_delete_still_accepts_uuid_form():
    # Legacy UUID-style ids must keep working (hyphens are allowed).
    model = BulkAlertDelete(alert_ids=["123e4567-e89b-12d3-a456-426614174000"])
    assert len(model.alert_ids) == 1


def test_bulk_delete_rejects_injection_like_id():
    with pytest.raises(ValidationError):
        BulkAlertDelete(alert_ids=["bad id with spaces/and*chars"])
