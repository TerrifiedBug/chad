"""Unit tests for the AI Detection Copilot service.

These tests monkeypatch the provider-call helper (``_call_provider``) to return
canned model output, so they never touch a real AI provider. The AI-disabled
path is exercised against the real ``_call_provider`` with an empty settings
table (provider defaults to ``disabled``).
"""

import pytest

from app.services import ai_copilot
from app.services.ai_copilot import AIDisabledError


@pytest.mark.asyncio
async def test_generate_sigma_rule_parses_output(monkeypatch):
    """generate_sigma_rule returns the yaml + explanation from model JSON."""
    canned = (
        '```json\n'
        '{"yaml": "title: Test Rule\\ndetection:\\n  selection:\\n'
        '    Image: bad.exe\\n  condition: selection\\nlevel: high",'
        ' "explanation": "Detects bad.exe execution."}\n'
        '```'
    )

    async def fake_call(db, prompt):
        # Ensure the description made it into the prompt.
        assert "suspicious powershell" in prompt
        return canned

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    result = await ai_copilot.generate_sigma_rule(
        db=None, description="suspicious powershell", logsource_hint="windows"
    )

    assert "title: Test Rule" in result["yaml"]
    assert result["explanation"] == "Detects bad.exe execution."


@pytest.mark.asyncio
async def test_generate_sigma_rule_tolerates_no_json(monkeypatch):
    """Unparseable model output yields empty strings, not an exception."""

    async def fake_call(db, prompt):
        return "I could not produce a rule."

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    result = await ai_copilot.generate_sigma_rule(db=None, description="x")
    assert result == {"yaml": "", "explanation": ""}


@pytest.mark.asyncio
async def test_summarize_alert_parses_output(monkeypatch):
    """summarize_alert returns a summary + list of recommended actions."""
    canned = (
        '{"summary": "A failed login burst from 10.0.0.5 targeted admin.",'
        ' "recommended_actions": ["Block 10.0.0.5", "Reset admin password"]}'
    )

    async def fake_call(db, prompt):
        # The alert document should be serialized into the prompt.
        assert "10.0.0.5" in prompt
        return canned

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    alert = {"source": {"ip": "10.0.0.5"}, "user": "admin", "rule_title": "Brute force"}
    result = await ai_copilot.summarize_alert(db=None, alert_document=alert)

    assert result["summary"].startswith("A failed login burst")
    assert result["recommended_actions"] == ["Block 10.0.0.5", "Reset admin password"]


@pytest.mark.asyncio
async def test_summarize_alert_coerces_string_action(monkeypatch):
    """A single-string recommended_actions field is coerced to a list."""

    async def fake_call(db, prompt):
        return '{"summary": "ok", "recommended_actions": "Investigate the host"}'

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    result = await ai_copilot.summarize_alert(db=None, alert_document={"id": "1"})
    assert result["recommended_actions"] == ["Investigate the host"]


@pytest.mark.asyncio
async def test_suggest_exceptions_parses_output(monkeypatch):
    """suggest_exceptions returns normalized suggestion dicts."""
    canned = (
        '{"suggestions": ['
        '{"field": "User", "operator": "equals", "value": "svc_backup",'
        ' "rationale": "Known service account", "risk": "Hides svc_backup abuse"},'
        '{"operator": "equals", "value": "no-field"}'  # skipped: no field
        ']}'
    )

    async def fake_call(db, prompt):
        assert "title: My Rule" in prompt
        return canned

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    result = await ai_copilot.suggest_exceptions(
        db=None,
        rule_yaml="title: My Rule",
        false_positive_examples=[{"User": "svc_backup"}],
    )

    assert len(result["suggestions"]) == 1
    suggestion = result["suggestions"][0]
    assert suggestion["field"] == "User"
    assert suggestion["operator"] == "equals"
    assert suggestion["value"] == "svc_backup"
    assert suggestion["risk"] == "Hides svc_backup abuse"


@pytest.mark.asyncio
async def test_suggest_exceptions_handles_missing_suggestions(monkeypatch):
    """A response with no suggestions array yields an empty list."""

    async def fake_call(db, prompt):
        return "{}"

    monkeypatch.setattr(ai_copilot, "_call_provider", fake_call)

    result = await ai_copilot.suggest_exceptions(
        db=None, rule_yaml="title: x", false_positive_examples=[]
    )
    assert result == {"suggestions": []}


@pytest.mark.asyncio
async def test_generate_rule_raises_when_ai_disabled(test_session):
    """With no AI setting configured, the provider defaults to disabled."""
    with pytest.raises(AIDisabledError):
        await ai_copilot.generate_sigma_rule(
            db=test_session, description="anything"
        )


@pytest.mark.asyncio
async def test_summarize_alert_raises_when_ai_disabled(test_session):
    with pytest.raises(AIDisabledError):
        await ai_copilot.summarize_alert(db=test_session, alert_document={"id": "1"})


@pytest.mark.asyncio
async def test_suggest_exceptions_raises_when_ai_disabled(test_session):
    with pytest.raises(AIDisabledError):
        await ai_copilot.suggest_exceptions(
            db=test_session, rule_yaml="title: x", false_positive_examples=[]
        )


@pytest.mark.asyncio
async def test_call_provider_dispatches_to_ollama(monkeypatch, test_session):
    """_call_provider reads the 'ai' setting and dispatches to the provider."""
    from app.services import ai_mapping
    from app.services.settings import set_setting

    await set_setting(
        test_session,
        "ai",
        {"ai_provider": "ollama", "ai_ollama_url": "http://x:11434", "ai_ollama_model": "llama3"},
    )

    captured = {}

    async def fake_ollama(url, model, prompt):
        captured["url"] = url
        captured["model"] = model
        return '{"yaml": "title: ok", "explanation": "ok"}'

    monkeypatch.setattr(ai_mapping, "_call_ollama", fake_ollama)

    result = await ai_copilot.generate_sigma_rule(
        db=test_session, description="hello"
    )
    assert result["yaml"] == "title: ok"
    assert captured["model"] == "llama3"
