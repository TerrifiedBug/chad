"""AI Detection Copilot API.

Thin HTTP layer over :mod:`app.services.ai_copilot`. Each endpoint requires the
relevant content permission, audits the (non-sensitive) request, and returns a
400 with a helpful message when no AI provider is configured.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission_dep
from app.db.session import get_db
from app.models.user import User
from app.schemas.ai_copilot import (
    GenerateRuleRequest,
    GenerateRuleResponse,
    SuggestExceptionsRequest,
    SuggestExceptionsResponse,
    SummarizeAlertRequest,
    SummarizeAlertResponse,
)
from app.services import ai_copilot
from app.services.ai_copilot import AIDisabledError
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/ai/copilot", tags=["ai-copilot"])


def _ai_error(exc: Exception) -> HTTPException:
    """Map a service-layer AI error to a 400 with a helpful message."""
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/generate-rule", response_model=GenerateRuleResponse)
async def generate_rule(
    data: GenerateRuleRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Draft a Sigma rule from a natural-language description."""
    try:
        result = await ai_copilot.generate_sigma_rule(
            db, data.description, data.logsource_hint
        )
    except (AIDisabledError, ValueError) as exc:
        raise _ai_error(exc) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI provider request failed: {exc}",
        ) from exc

    await audit_log(
        db,
        current_user.id,
        "ai_copilot.generate_rule",
        "ai_copilot",
        None,
        {"logsource_hint": data.logsource_hint},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return GenerateRuleResponse(**result)


@router.post("/summarize-alert", response_model=SummarizeAlertResponse)
async def summarize_alert(
    data: SummarizeAlertRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_alerts"))],
):
    """Summarize a single alert document and recommend next actions."""
    try:
        result = await ai_copilot.summarize_alert(db, data.alert_document)
    except (AIDisabledError, ValueError) as exc:
        raise _ai_error(exc) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI provider request failed: {exc}",
        ) from exc

    await audit_log(
        db,
        current_user.id,
        "ai_copilot.summarize_alert",
        "ai_copilot",
        str(data.alert_document.get("alert_id") or data.alert_document.get("id") or ""),
        {},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return SummarizeAlertResponse(**result)


@router.post("/suggest-exceptions", response_model=SuggestExceptionsResponse)
async def suggest_exceptions(
    data: SuggestExceptionsRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Propose tuning exceptions for a rule from false-positive examples."""
    try:
        result = await ai_copilot.suggest_exceptions(
            db, data.rule_yaml, data.false_positive_examples
        )
    except (AIDisabledError, ValueError) as exc:
        raise _ai_error(exc) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI provider request failed: {exc}",
        ) from exc

    await audit_log(
        db,
        current_user.id,
        "ai_copilot.suggest_exceptions",
        "ai_copilot",
        None,
        {"fp_example_count": len(data.false_positive_examples)},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return SuggestExceptionsResponse(**result)
