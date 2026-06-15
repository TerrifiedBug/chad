"""Detection-as-Code CI API (rule lint + FP backtest + coverage gate).

Exposes the :mod:`app.services.rule_ci` pipeline:

  - ``POST /rule-ci/check``            run CI over an arbitrary rule YAML.
  - ``POST /rule-ci/{rule_id}/check``  run CI over a stored rule (loads its YAML
                                       + index pattern, and reads persisted
                                       ATT&CK mappings for the coverage check).

Both require ``manage_rules`` and audit the run. OpenSearch is optional — the
OS-dependent checks degrade to ``skipped`` when it isn't configured.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_opensearch_client_optional, require_permission_dep
from app.db.session import get_db
from app.models.rule import Rule
from app.models.user import User
from app.schemas.rule_ci import RuleCICheckItem, RuleCICheckRequest, RuleCIReport
from app.services.audit import audit_log
from app.services.rule_ci import CIOptions, CIReport, run_ci
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rule-ci", tags=["rule-ci"])


def _options_from_request(req: RuleCICheckRequest) -> CIOptions:
    """Build CIOptions from request overrides, falling back to service defaults."""
    options = CIOptions(run_backtest=req.run_backtest)
    if req.fp_threshold is not None:
        options.fp_threshold = req.fp_threshold
    if req.backtest_days is not None:
        options.backtest_days = req.backtest_days
    return options


def _to_report_schema(report: CIReport) -> RuleCIReport:
    """Convert the service dataclass report into its Pydantic response model."""
    return RuleCIReport(
        passed=report.passed,
        summary=report.summary,
        checks=[
            RuleCICheckItem(
                name=c.name,
                status=c.status,
                detail=c.detail,
                data=c.data,
            )
            for c in report.checks
        ],
    )


@router.post("/check", response_model=RuleCIReport)
async def check_rule_yaml(
    request: Request,
    body: RuleCICheckRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Run the CI pipeline over an arbitrary (possibly unsaved) rule YAML."""
    report = await run_ci(
        db=db,
        os_client=os_client,
        rule_yaml=body.yaml_content,
        index_pattern_id=body.index_pattern_id,
        options=_options_from_request(body),
    )

    await audit_log(
        db,
        current_user.id,
        "rule_ci.check",
        "rule",
        None,
        {
            "passed": report.passed,
            "index_pattern_id": str(body.index_pattern_id) if body.index_pattern_id else None,
            "statuses": {c.name: c.status for c in report.checks},
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return _to_report_schema(report)


@router.post("/{rule_id}/check", response_model=RuleCIReport)
async def check_stored_rule(
    rule_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    body: RuleCICheckRequest | None = None,
):
    """Run the CI pipeline over a stored rule.

    Loads the rule's YAML and index pattern; the optional body may still carry
    threshold overrides. The rule id is passed through so the coverage check can
    read persisted ATT&CK mappings.
    """
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    # Body is optional for stored rules — synthesize defaults when absent.
    overrides = body or RuleCICheckRequest(yaml_content=rule.yaml_content)

    report = await run_ci(
        db=db,
        os_client=os_client,
        rule_yaml=rule.yaml_content,
        index_pattern_id=rule.index_pattern_id,
        options=_options_from_request(overrides),
        rule_id=rule.id,
    )

    await audit_log(
        db,
        current_user.id,
        "rule_ci.check",
        "rule",
        str(rule.id),
        {
            "passed": report.passed,
            "statuses": {c.name: c.status for c in report.checks},
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return _to_report_schema(report)
