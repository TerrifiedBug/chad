"""AI-powered field mapping suggestions."""

import json
import re
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt
from app.services.settings import get_setting

AI_PROMPT_TEMPLATE = """You are a security data field mapping expert. Your task is to map Sigma detection rule field names to the actual field names present in a user's log data.

## Context
- Sigma rules use the Sigma taxonomy - a vendor-neutral field naming standard for detection rules
- User logs may use different schemas: ECS (Elastic), OCSF, vendor-specific (auditd, sysmon), or custom
- A correct mapping allows Sigma detection rules to query the user's actual log fields

## Your Task
Map each unmapped Sigma field to the best matching field from the available log fields.

**Logsource context:**
{logsource}

**Unmapped Sigma fields:**
{sigma_fields}

**Available fields in user's logs:**
{log_fields}

## Guidelines
1. Match based on semantic meaning, not just name similarity
2. Common Sigma fields and their typical equivalents:
   - SourceIp → src_ip, source.ip, client.ip
   - DestinationIp → dst_ip, destination.ip, server.ip
   - User → user.name, acct, username
   - Image → process.executable, exe, process.name
   - CommandLine → process.command_line, process.args, cmdline, command
   - ParentImage → process.parent.executable, parent_exe
   - TargetFilename → file.path, filepath, target_path
   - SourcePort → src_port, source.port, client.port
   - DestinationPort → dst_port, destination.port, server.port
3. If no good match exists, return null for that field
4. When uncertain, prefer the more specific match
5. Consider the logsource context when making decisions
6. IMPORTANT: Only suggest field names exactly as they appear in the available fields list. Do not add suffixes like .keyword - the system handles field type optimization automatically.

## Response Format
Return valid JSON only:
{{"mappings": [
    {{"sigma_field": "FieldName", "target_field": "matched_field_or_null", "confidence": 0.0_to_1.0, "reason": "brief explanation"}}
]}}"""


@dataclass
class AISuggestion:
    sigma_field: str
    target_field: str | None
    confidence: float
    reason: str


def build_prompt(
    sigma_fields: list[str],
    log_fields: list[str],
    logsource: dict | None = None,
) -> str:
    """Build the AI prompt with field lists."""
    return AI_PROMPT_TEMPLATE.format(
        logsource=json.dumps(logsource or {}, indent=2),
        sigma_fields="\n".join(f"- {f}" for f in sigma_fields),
        log_fields="\n".join(f"- {f}" for f in log_fields),
    )


def parse_ai_response(response: str) -> list[AISuggestion]:
    """Parse AI response into suggestions."""
    # Try to extract JSON from response (may be in markdown code block)
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
    if json_match:
        response = json_match.group(1)

    # Try to find JSON object directly
    try:
        # Find the first { and last }
        start = response.find("{")
        end = response.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(response[start:end])
            mappings = data.get("mappings", [])
            return [
                AISuggestion(
                    sigma_field=m.get("sigma_field", ""),
                    target_field=m.get("target_field"),
                    confidence=float(m.get("confidence", 0)),
                    reason=m.get("reason", ""),
                )
                for m in mappings
                if m.get("sigma_field")  # Skip entries without sigma_field
            ]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        pass

    return []


async def _call_ollama(url: str, model: str, prompt: str) -> str:
    """Call Ollama API."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{url.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
        )
        response.raise_for_status()
        return response.json().get("response", "")


async def _call_openai(api_key: str, model: str, prompt: str) -> str:
    """Call OpenAI API."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            },
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


async def _call_anthropic(api_key: str, model: str, prompt: str) -> str:
    """Call Anthropic API."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        return response.json()["content"][0]["text"]


async def suggest_mappings(
    db: AsyncSession,
    sigma_fields: list[str],
    log_fields: list[str],
    logsource: dict | None = None,
) -> list[AISuggestion]:
    """
    Get AI suggestions for field mappings.

    Reads AI provider configuration from settings and calls the appropriate API.
    """
    # Get AI settings
    ai_settings = await get_setting(db, "ai") or {}
    provider = ai_settings.get("ai_provider", "disabled")

    if provider == "disabled":
        raise ValueError("AI provider not configured")

    prompt = build_prompt(sigma_fields, log_fields, logsource)

    if provider == "ollama":
        url = ai_settings.get("ai_ollama_url", "http://localhost:11434")
        model = ai_settings.get("ai_ollama_model", "llama3")
        response = await _call_ollama(url, model, prompt)

    elif provider == "openai":
        api_key = ai_settings.get("ai_openai_key", "")
        if api_key:
            try:
                api_key = decrypt(api_key)
            except Exception:
                raise ValueError("Failed to decrypt OpenAI API key")
        if not api_key:
            raise ValueError("OpenAI API key not configured")
        model = ai_settings.get("ai_openai_model", "gpt-4o")
        response = await _call_openai(api_key, model, prompt)

    elif provider == "anthropic":
        api_key = ai_settings.get("ai_anthropic_key", "")
        if api_key:
            try:
                api_key = decrypt(api_key)
            except Exception:
                raise ValueError("Failed to decrypt Anthropic API key")
        if not api_key:
            raise ValueError("Anthropic API key not configured")
        model = ai_settings.get("ai_anthropic_model", "claude-sonnet-4-20250514")
        response = await _call_anthropic(api_key, model, prompt)

    else:
        raise ValueError(f"Unknown AI provider: {provider}")

    return parse_ai_response(response)
