"""Tests for nested JSON field matching in rule testing."""

import uuid

from app.schemas.rule import RuleTestRequest


def test_rule_test_request_accepts_index_pattern_id():
    """Schema should accept optional index_pattern_id."""
    req = RuleTestRequest(
        yaml_content="title: Test\nstatus: test\nlogsource:\n  product: test\ndetection:\n  sel:\n    source.ip: '1.2.3.4'\n  condition: sel",
        sample_logs=[{"source": {"ip": "1.2.3.4"}}],
        index_pattern_id=uuid.uuid4(),
    )
    assert req.index_pattern_id is not None


def test_rule_test_request_index_pattern_id_optional():
    """Schema should work without index_pattern_id (backwards compatible)."""
    req = RuleTestRequest(
        yaml_content="title: Test\nstatus: test\nlogsource:\n  product: test\ndetection:\n  sel:\n    fieldA: 'test'\n  condition: sel",
        sample_logs=[{"fieldA": "test"}],
    )
    assert req.index_pattern_id is None
