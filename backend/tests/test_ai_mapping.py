"""Tests for AI mapping service."""


from app.services.ai_mapping import (
    build_prompt,
    parse_ai_response,
)


class TestBuildPrompt:
    """Test prompt building."""

    def test_builds_prompt_with_fields(self):
        prompt = build_prompt(
            sigma_fields=["SourceIp", "User"],
            log_fields=["src_ip", "acct", "timestamp"],
            logsource={"product": "linux", "service": "auditd"},
        )
        assert "SourceIp" in prompt
        assert "User" in prompt
        assert "src_ip" in prompt
        assert "auditd" in prompt

    def test_builds_prompt_without_logsource(self):
        prompt = build_prompt(
            sigma_fields=["CommandLine"],
            log_fields=["cmdline", "process.command_line"],
            logsource=None,
        )
        assert "CommandLine" in prompt
        assert "cmdline" in prompt

    def test_builds_prompt_with_empty_logsource(self):
        prompt = build_prompt(
            sigma_fields=["Image"],
            log_fields=["exe", "process.executable"],
            logsource={},
        )
        assert "Image" in prompt


class TestParseResponse:
    """Test AI response parsing."""

    def test_parse_valid_response(self):
        response = '''{"mappings": [
            {"sigma_field": "SourceIp", "target_field": "src_ip", "confidence": 0.95, "reason": "Match"},
            {"sigma_field": "User", "target_field": null, "confidence": 0, "reason": "No match"}
        ]}'''
        suggestions = parse_ai_response(response)
        assert len(suggestions) == 2
        assert suggestions[0].sigma_field == "SourceIp"
        assert suggestions[0].target_field == "src_ip"
        assert suggestions[0].confidence == 0.95
        assert suggestions[1].target_field is None

    def test_parse_handles_json_in_markdown(self):
        response = '''Here's the mapping:
        ```json
        {"mappings": [{"sigma_field": "SourceIp", "target_field": "src_ip", "confidence": 0.9, "reason": "Match"}]}
        ```'''
        suggestions = parse_ai_response(response)
        assert len(suggestions) == 1
        assert suggestions[0].sigma_field == "SourceIp"

    def test_parse_handles_json_in_markdown_without_lang(self):
        response = '''Here's the mapping:
        ```
        {"mappings": [{"sigma_field": "User", "target_field": "username", "confidence": 0.85, "reason": "Semantic match"}]}
        ```'''
        suggestions = parse_ai_response(response)
        assert len(suggestions) == 1
        assert suggestions[0].sigma_field == "User"

    def test_parse_handles_invalid_json(self):
        response = "This is not JSON"
        suggestions = parse_ai_response(response)
        assert suggestions == []

    def test_parse_handles_empty_mappings(self):
        response = '{"mappings": []}'
        suggestions = parse_ai_response(response)
        assert suggestions == []

    def test_parse_handles_missing_fields(self):
        response = '{"mappings": [{"sigma_field": "Test"}]}'
        suggestions = parse_ai_response(response)
        # Should skip malformed entries
        assert len(suggestions) == 1
        assert suggestions[0].target_field is None
        assert suggestions[0].confidence == 0

    def test_parse_handles_extra_text_around_json(self):
        response = '''I've analyzed the fields and here's my recommendation:

{"mappings": [
    {"sigma_field": "DestinationIp", "target_field": "dst_ip", "confidence": 0.92, "reason": "Direct match"}
]}

Let me know if you need any clarification.'''
        suggestions = parse_ai_response(response)
        assert len(suggestions) == 1
        assert suggestions[0].sigma_field == "DestinationIp"
        assert suggestions[0].target_field == "dst_ip"
