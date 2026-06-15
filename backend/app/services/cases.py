"""Case management service — investigation lifecycle + timeline.

Keeps the append-only timeline (:class:`CaseEvent`) consistent with every
mutation: status changes, assignments, alert links, and comments all record an
event so a case reads as a coherent investigation history.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import (
    CLOSED_STATUSES,
    Case,
    CaseAlert,
    CaseComment,
    CaseEvent,
    CaseEventType,
)
from app.models.user import User


async def next_case_number(db: AsyncSession) -> int:
    """Next sequential case number (max + 1). 1 on an empty table.

    Races are acceptable for a human-facing number; the unique constraint on
    ``cases.number`` turns a collision into a retryable error rather than a
    duplicate.
    """
    current = (await db.execute(select(func.max(Case.number)))).scalar()
    return (current or 0) + 1


def record_event(
    db: AsyncSession,
    case_id: uuid.UUID,
    event_type: CaseEventType,
    actor_id: uuid.UUID | None,
    message: str,
    metadata: dict | None = None,
) -> CaseEvent:
    """Append a timeline event (flush only — caller owns the commit)."""
    event = CaseEvent(
        case_id=case_id,
        event_type=event_type.value,
        actor_id=actor_id,
        message=message,
        event_metadata=metadata,
    )
    db.add(event)
    return event


async def alert_count(db: AsyncSession, case_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count(CaseAlert.id)).where(CaseAlert.case_id == case_id)
        )
    ).scalar() or 0


async def email_map(db: AsyncSession, user_ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    """Resolve a set of user ids → emails in one query (for response enrichment)."""
    ids = [uid for uid in user_ids if uid is not None]
    if not ids:
        return {}
    rows = (await db.execute(select(User.id, User.email).where(User.id.in_(ids)))).all()
    return {row[0]: row[1] for row in rows}


def apply_close_semantics(case: Case, new_status: str) -> None:
    """Keep ``closed_at`` in sync with the status transition."""
    if new_status in CLOSED_STATUSES and case.closed_at is None:
        case.closed_at = datetime.now(UTC)
    elif new_status not in CLOSED_STATUSES:
        case.closed_at = None


async def soft_delete_comment(comment: CaseComment) -> None:
    comment.deleted_at = datetime.now(UTC)
