# backend/app/schemas/sigmahq.py
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class SigmaHQRuleType(str, Enum):
    DETECTION = "detection"
    THREAT_HUNTING = "threat_hunting"
    EMERGING_THREATS = "emerging_threats"


class SigmaHQStatusResponse(BaseModel):
    cloned: bool
    commit_hash: str | None = None
    rule_counts: dict[str, int] | None = None
    repo_url: str | None = None


class SigmaHQSyncResponse(BaseModel):
    success: bool
    message: str
    commit_hash: str | None = None
    rule_counts: dict[str, int] | None = None
    error: str | None = None


class SigmaHQCategoryTree(BaseModel):
    categories: dict


class SigmaHQRule(BaseModel):
    title: str
    status: str
    severity: str
    description: str
    tags: list[str]
    path: str
    filename: str


class SigmaHQRulesListResponse(BaseModel):
    rules: list[SigmaHQRule]
    total: int


class SigmaHQRuleContentResponse(BaseModel):
    path: str
    content: str
    metadata: dict | None = None


class SigmaHQImportRequest(BaseModel):
    rule_path: str
    index_pattern_id: UUID
    rule_type: SigmaHQRuleType = SigmaHQRuleType.DETECTION


class SigmaHQImportResponse(BaseModel):
    success: bool
    rule_id: str
    title: str
    message: str


class SigmaHQSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=100, ge=1, le=1000)
    rule_type: SigmaHQRuleType = SigmaHQRuleType.DETECTION
