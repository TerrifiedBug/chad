"""Tests for rule model."""


def test_rule_source_includes_misp():
    """RuleSource enum should include MISP."""
    from app.models.rule import RuleSource
    assert hasattr(RuleSource, 'MISP')
    assert RuleSource.MISP.value == "misp"
