"""Tests for the Sigma translation service."""

import pytest
from app.services.sigma import sigma_service


class TestSigmaParsing:
    """Tests for parsing Sigma rules."""

    def test_parse_valid_rule(self):
        """Parse a valid Sigma rule."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        rule = sigma_service.parse_rule(yaml_content)
        assert rule is not None
        assert rule.title == "Test Rule"

    def test_parse_invalid_yaml(self):
        """Parsing invalid YAML raises ValueError."""
        yaml_content = """
title: Test
  invalid: indent
"""
        with pytest.raises(ValueError) as exc:
            sigma_service.parse_rule(yaml_content)
        assert "Invalid YAML" in str(exc.value)

    def test_parse_missing_required_fields(self):
        """Parsing YAML missing required Sigma fields raises ValueError."""
        yaml_content = """
title: Test Rule
# Missing logsource and detection
"""
        with pytest.raises(ValueError) as exc:
            sigma_service.parse_rule(yaml_content)
        assert "Invalid Sigma rule" in str(exc.value)


class TestSigmaValidation:
    """Tests for validating Sigma rules."""

    def test_validate_valid_rule(self):
        """Validate a valid Sigma rule returns no errors."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        errors = sigma_service.validate_rule(yaml_content)
        assert len(errors) == 0

    def test_validate_invalid_yaml(self):
        """Validate invalid YAML returns syntax error."""
        yaml_content = """
title: Test
  invalid: indent
"""
        errors = sigma_service.validate_rule(yaml_content)
        assert len(errors) > 0
        assert errors[0].type == "syntax"

    def test_validate_missing_title(self):
        """Validate rule missing title returns schema error."""
        yaml_content = """
logsource:
    product: windows
detection:
    selection:
        CommandLine: test
    condition: selection
"""
        errors = sigma_service.validate_rule(yaml_content)
        assert len(errors) > 0
        assert errors[0].type == "schema"
        assert "title" in errors[0].message.lower()

    def test_validate_missing_logsource(self):
        """Validate rule missing logsource returns schema error."""
        yaml_content = """
title: Test Rule
detection:
    selection:
        CommandLine: test
    condition: selection
"""
        errors = sigma_service.validate_rule(yaml_content)
        assert len(errors) > 0
        assert errors[0].type == "schema"
        assert "logsource" in errors[0].message.lower()

    def test_validate_missing_detection(self):
        """Validate rule missing detection returns schema error."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
"""
        errors = sigma_service.validate_rule(yaml_content)
        assert len(errors) > 0
        assert errors[0].type == "schema"
        assert "detection" in errors[0].message.lower()


class TestSigmaTranslation:
    """Tests for translating Sigma rules to OpenSearch queries."""

    def test_translate_simple_rule(self):
        """Translate a simple Sigma rule to OpenSearch query."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True
        assert result.query is not None
        assert "query" in result.query
        # Should contain whoami in the query
        assert "whoami" in str(result.query)

    def test_translate_multiple_conditions(self):
        """Translate rule with multiple conditions."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        CommandLine|contains: whoami
    selection2:
        Image|endswith: cmd.exe
    condition: selection1 or selection2
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True
        assert result.query is not None


class TestFieldExtraction:
    """Tests for extracting fields from Sigma rules."""

    def test_extract_single_field(self):
        """Extract single field from rule."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True
        assert result.fields is not None
        assert "CommandLine" in result.fields

    def test_extract_multiple_fields(self):
        """Extract multiple fields from rule."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
        Image|endswith: cmd.exe
        ParentImage: explorer.exe
    condition: selection
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True
        assert result.fields is not None
        assert "CommandLine" in result.fields
        assert "Image" in result.fields
        assert "ParentImage" in result.fields


class TestSampleLogMatching:
    """Tests for matching sample logs against rules."""

    def test_match_simple_contains(self):
        """Match log with contains condition."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True

        log_match = {"CommandLine": "cmd.exe /c whoami"}
        log_nomatch = {"CommandLine": "notepad.exe"}

        assert sigma_service.test_against_log(result.query, log_match) is True
        assert sigma_service.test_against_log(result.query, log_nomatch) is False

    def test_match_nested_field(self):
        """Match log with nested field."""
        yaml_content = """
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        process.name: cmd.exe
    condition: selection
"""
        result = sigma_service.translate_and_validate(yaml_content)
        assert result.success is True

        log_match = {"process": {"name": "cmd.exe"}}
        log_nomatch = {"process": {"name": "notepad.exe"}}

        assert sigma_service.test_against_log(result.query, log_match) is True
        assert sigma_service.test_against_log(result.query, log_nomatch) is False
