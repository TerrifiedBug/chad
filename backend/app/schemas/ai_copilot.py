"""Request/response schemas for the AI Detection Copilot API."""

from pydantic import BaseModel, ConfigDict, Field


class GenerateRuleRequest(BaseModel):
    """Request to draft a Sigma rule from a natural-language description."""

    description: str = Field(..., min_length=1, description="What the rule should detect")
    logsource_hint: str | None = Field(
        default=None,
        description="Optional logsource context, e.g. 'windows / process_creation'",
    )


class GenerateRuleResponse(BaseModel):
    """Generated Sigma rule plus a plain-English explanation."""

    model_config = ConfigDict(from_attributes=True)

    yaml: str
    explanation: str


class SummarizeAlertRequest(BaseModel):
    """Request to summarize a single alert document."""

    alert_document: dict = Field(..., description="The raw alert / event document")


class SummarizeAlertResponse(BaseModel):
    """Analyst-friendly alert summary and recommended next steps."""

    model_config = ConfigDict(from_attributes=True)

    summary: str
    recommended_actions: list[str] = Field(default_factory=list)


class SuggestExceptionsRequest(BaseModel):
    """Request to propose tuning exceptions from false-positive examples."""

    rule_yaml: str = Field(..., min_length=1, description="The Sigma rule YAML to tune")
    false_positive_examples: list[dict] = Field(
        default_factory=list,
        description="Example events that fired but are benign",
    )


class ExceptionSuggestion(BaseModel):
    """A single proposed tuning exception."""

    model_config = ConfigDict(from_attributes=True)

    field: str
    operator: str
    value: object = ""
    rationale: str = ""
    risk: str = ""


class SuggestExceptionsResponse(BaseModel):
    """Set of proposed tuning exceptions."""

    model_config = ConfigDict(from_attributes=True)

    suggestions: list[ExceptionSuggestion] = Field(default_factory=list)
