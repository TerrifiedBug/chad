"""Rule exceptions sub-router: list, create, update, and delete per-rule exceptions."""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from opensearchpy import OpenSearch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    get_opensearch_client_optional,
    require_permission_dep,
)
from app.db.session import get_db
from app.models.rule import Rule
from app.models.rule_exception import ExceptionOperator, RuleException
from app.models.user import User
from app.schemas.rule_exception import (
    RuleExceptionCreate,
    RuleExceptionResponse,
    RuleExceptionUpdate,
)
from app.services.audit import audit_log
from app.utils.request import get_client_ip

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/{rule_id}/exceptions", response_model=list[RuleExceptionResponse])
async def list_rule_exceptions(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """List all exceptions for a rule."""
    # Verify rule exists
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    result = await db.execute(
        select(RuleException)
        .where(RuleException.rule_id == rule_id)
        .order_by(RuleException.created_at.desc())
    )
    return result.scalars().all()


@router.post(
    "/{rule_id}/exceptions",
    response_model=RuleExceptionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule_exception(
    rule_id: UUID,
    exception_data: RuleExceptionCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    os_client: Annotated[OpenSearch | None, Depends(get_opensearch_client_optional)],
):
    """Create a new exception for a rule."""
    # Verify rule exists
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Check for duplicate or overlapping exceptions
    existing_result = await db.execute(
        select(RuleException).where(
            RuleException.rule_id == rule_id,
            RuleException.field == exception_data.field,
            RuleException.is_active == True,  # noqa: E712
        )
    )
    existing_exceptions = existing_result.scalars().all()

    warning = None
    for exc in existing_exceptions:
        # Exact duplicate - block
        if exc.value == exception_data.value and exc.operator == exception_data.operator:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Duplicate exception already exists for {exception_data.field}={exception_data.value}",
            )

        # Check for overlap - warn but allow
        # If new exception uses wildcard (contains/regex) and existing is exact
        if exception_data.operator == ExceptionOperator.CONTAINS and exc.operator == ExceptionOperator.EQUALS:
            if exception_data.value.lower() in exc.value.lower():
                warning = f"This pattern would cover existing exception '{exc.value}'"
        elif exc.operator == ExceptionOperator.CONTAINS and exception_data.operator == ExceptionOperator.EQUALS:
            if exc.value.lower() in exception_data.value.lower():
                warning = f"This value is already covered by existing pattern '{exc.value}'"

    # If group_id is provided, add to existing group (AND logic)
    # Otherwise, a new group_id is auto-generated (new OR condition)
    exception = RuleException(
        rule_id=rule_id,
        field=exception_data.field,
        operator=exception_data.operator,
        value=exception_data.value,
        reason=exception_data.reason,
        created_by=current_user.id,
        **({"group_id": exception_data.group_id} if exception_data.group_id else {}),
    )
    db.add(exception)
    await db.commit()
    await db.refresh(exception)
    await audit_log(db, current_user.id, "exception.create", "rule_exception", str(exception.id), {"rule_id": str(rule_id), "field": exception.field, "change_reason": exception_data.change_reason}, ip_address=get_client_ip(request))
    await db.commit()

    # If created from an alert, update alert status and record exception reference
    if exception_data.alert_id and os_client:
        try:
            os_client.update(
                index="chad-alerts-*",
                id=exception_data.alert_id,
                body={
                    "doc": {
                        "status": "false_positive",
                        "exception_created": {
                            "exception_id": str(exception.id),
                            "field": exception.field,
                            "value": exception.value,
                            "match_type": exception.operator.value,
                            "created_at": datetime.now(UTC).isoformat(),
                        }
                    }
                },
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to update alert status for exception: %s", str(e)
            )

    # Return response with optional warning
    response = RuleExceptionResponse.model_validate(exception)
    if warning:
        response.warning = warning
    return response


@router.patch(
    "/{rule_id}/exceptions/{exception_id}",
    response_model=RuleExceptionResponse,
)
async def update_rule_exception(
    rule_id: UUID,
    exception_id: UUID,
    exception_data: RuleExceptionUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
):
    """Update an exception (change fields or toggle active state)."""
    result = await db.execute(
        select(RuleException).where(
            RuleException.id == exception_id,
            RuleException.rule_id == rule_id,
        )
    )
    exception = result.scalar_one_or_none()

    if exception is None:
        raise HTTPException(status_code=404, detail="Exception not found")

    update_data = exception_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(exception, field, value)

    await db.commit()
    await db.refresh(exception)
    await audit_log(db, current_user.id, "exception.update", "rule_exception", str(exception.id), {"rule_id": str(rule_id), "change_reason": exception_data.change_reason}, ip_address=get_client_ip(request))
    await db.commit()
    return exception


@router.delete(
    "/{rule_id}/exceptions/{exception_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_rule_exception(
    rule_id: UUID,
    exception_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission_dep("manage_rules"))],
    change_reason: str = Body(..., min_length=1, max_length=10000, embed=True),
):
    """Delete an exception."""
    result = await db.execute(
        select(RuleException).where(
            RuleException.id == exception_id,
            RuleException.rule_id == rule_id,
        )
    )
    exception = result.scalar_one_or_none()

    if exception is None:
        raise HTTPException(status_code=404, detail="Exception not found")

    # Capture details before delete
    await audit_log(db, current_user.id, "exception.delete", "rule_exception", str(exception_id), {"rule_id": str(rule_id), "change_reason": change_reason}, ip_address=get_client_ip(request))
    await db.delete(exception)
    await db.commit()


# Rule Fields Endpoint (for correlation)


