"""Pydantic schemas for environments (Model B per-env deployment scopes)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    team_id: UUID | None = None
    is_default: bool = False
    require_deploy_approval: bool = False
    opensearch_index_prefix: str | None = Field(default=None, max_length=255)
    color: str | None = Field(default=None, max_length=32)


class EnvironmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    is_default: bool | None = None
    require_deploy_approval: bool | None = None
    opensearch_index_prefix: str | None = Field(default=None, max_length=255)
    color: str | None = Field(default=None, max_length=32)


class EnvironmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None = None
    team_id: UUID | None = None
    is_default: bool
    require_deploy_approval: bool
    opensearch_index_prefix: str | None = None
    color: str | None = None
    created_at: datetime
    updated_at: datetime
    # Per-env deploy aggregates (filled by the list/detail endpoints).
    rule_count: int = 0
    deployed_count: int = 0


# --------------------------------------------------------------------------- #
# Git config-as-code sync (Feature C). One-way push only: ``off`` | ``push``.
# --------------------------------------------------------------------------- #
GitOpsMode = Literal["off", "push"]


class EnvGitConfigUpdate(BaseModel):
    """Set/clear an env's git sync config. ``git_token`` is write-only."""

    git_repo_url: str | None = Field(default=None, max_length=1024)
    git_branch: str = Field(default="main", min_length=1, max_length=255)
    # Send a new token to rotate it; omit (None) to leave the stored one intact.
    git_token: str | None = Field(default=None, max_length=4096)
    gitops_mode: GitOpsMode = "off"
    git_provider: str | None = Field(default=None, max_length=50)


class EnvGitConfigResponse(BaseModel):
    """Git config as exposed to the UI — the token is masked, never returned."""

    model_config = ConfigDict(from_attributes=True)

    git_repo_url: str | None = None
    git_branch: str = "main"
    gitops_mode: str = "off"
    git_provider: str | None = None
    # True when a token is stored (so the UI can show "configured" without it).
    has_token: bool = False


class EnvGitTestResponse(BaseModel):
    success: bool
    error: str | None = None


# --------------------------------------------------------------------------- #
# Promotion (advance a target env's pinned version to the source env's, Model B)
# --------------------------------------------------------------------------- #
class PromoteRequest(BaseModel):
    """Promote one or more rules from a source env into the target env.

    The target env is the path parameter; the source env is named here. For each
    rule the *version currently deployed in the source env* is deployed (pinned)
    into the target env — the rule definition is never copied (Model B).
    """

    rule_ids: list[UUID] = Field(..., min_length=1)
    source_environment_id: UUID
    change_reason: str = Field(..., min_length=1, max_length=10000)


class PromoteRuleResult(BaseModel):
    """Per-rule outcome of a promotion (no silent partial-promote)."""

    rule_id: UUID
    # promoted = applied into target; pending = filed for approval (target gated);
    # ineligible = preflight rejected it (reason set).
    status: Literal["promoted", "pending", "ineligible"]
    source_version: int | None = None
    reason: str | None = None


class PromoteResponse(BaseModel):
    """Result of a promotion call.

    ``deployment_request_id`` is set when the target env is gated and a single
    dual-control request was filed for the eligible rules (those items are
    ``pending``). Ineligible rules are reported but never filed.
    """

    target_environment_id: UUID
    source_environment_id: UUID
    deployment_request_id: UUID | None = None
    results: list[PromoteRuleResult]
