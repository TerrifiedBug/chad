"""Pydantic schemas for ATT&CK Coverage Map API."""
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class TechniqueBase(BaseModel):
    """Base technique fields for matrix display."""

    id: str
    name: str
    tactic_id: str
    tactic_name: str
    parent_id: str | None = None
    is_subtechnique: bool = False


class TechniqueResponse(TechniqueBase):
    """Full technique details returned by API."""

    description: str | None = None
    url: str | None = None
    platforms: list[str] | None = None
    data_sources: list[str] | None = None
    updated_at: datetime

    class Config:
        from_attributes = True


class TechniqueWithCoverage(TechniqueBase):
    """Technique with rule count for matrix display."""

    rule_count: int = 0


class TacticWithTechniques(BaseModel):
    """Tactic grouping for matrix columns."""

    id: str
    name: str
    techniques: list[TechniqueWithCoverage]


class MatrixResponse(BaseModel):
    """Full matrix structure for frontend rendering."""

    tactics: list[TacticWithTechniques]


class TechniqueCoverageStats(BaseModel):
    """Coverage statistics for a single technique."""

    total: int = 0
    deployed: int = 0


class CoverageResponse(BaseModel):
    """Coverage counts per technique with total and deployed breakdown."""

    coverage: dict[str, TechniqueCoverageStats]  # {"T1059": {"total": 5, "deployed": 3}, ...}


class LinkedRuleResponse(BaseModel):
    """Rule summary for technique detail panel."""

    id: UUID
    title: str
    severity: str
    status: str
    index_pattern_name: str | None = None


class TechniqueDetailResponse(BaseModel):
    """Full technique details with linked rules."""

    technique: TechniqueResponse
    rules: list[LinkedRuleResponse]
    sub_techniques: list[TechniqueWithCoverage] = []


class SyncResponse(BaseModel):
    """Response from manual sync operation."""

    success: bool
    message: str
    techniques_updated: int = 0
    new_techniques: int = 0
    error: str | None = None


class SyncStatusResponse(BaseModel):
    """Current sync status for settings display."""

    last_sync: datetime | None = None
    next_scheduled: datetime | None = None
    sync_enabled: bool = False
    technique_count: int = 0
    frequency: str | None = None  # "daily", "weekly", "monthly"
