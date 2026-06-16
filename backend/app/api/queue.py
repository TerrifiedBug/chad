"""Queue management API endpoints."""

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.redis import get_redis_queue
from app.db.session import get_db
from app.models.user import User
from app.schemas.queue import QueueSettings, QueueSettingsUpdate
from app.services.queue_settings import get_queue_settings
from app.services.settings import get_setting, set_setting

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/queue", tags=["queue"])


class QueueStatsResponse(BaseModel):
    """Queue statistics response."""
    total_depth: int
    queues: dict[str, int]
    dead_letter_count: int


class DeadLetterMessage(BaseModel):
    """Dead letter message structure."""
    id: str
    original_stream: str
    original_id: str
    data: dict
    reason: str


class DeadLetterResponse(BaseModel):
    """Dead letter queue response."""
    count: int
    messages: list[DeadLetterMessage]


@router.get("/settings", response_model=QueueSettings)
async def get_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Get current queue settings.

    Requires admin role.
    """
    return await get_queue_settings(db)


@router.put("/settings", response_model=QueueSettings)
async def update_settings(
    settings: QueueSettingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Update queue settings.

    Requires admin role.
    """
    # Get current settings
    current = await get_setting(db, "queue_settings") or {}

    # Merge updates
    update_dict = settings.model_dump(exclude_unset=True)
    current.update(update_dict)

    # Save
    await set_setting(db, "queue_settings", current)

    return await get_queue_settings(db)


@router.get("/stats", response_model=QueueStatsResponse)
async def get_queue_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Get queue statistics.

    Returns current queue depths for all indexes and dead letter count.
    Requires admin role.
    """
    try:
        redis = await get_redis_queue()

        queues = {}
        total_depth = 0
        cursor = 0

        while True:
            cursor, keys = await redis.scan(cursor, match="chad:logs:*", count=100)
            for key in keys:
                if "dead-letter" not in key:
                    depth = await redis.xlen(key)
                    index = key.replace("chad:logs:", "")
                    queues[index] = depth
                    total_depth += depth
            if cursor == 0:
                break

        dead_letter_count = await redis.xlen("chad:logs:dead-letter")

        return QueueStatsResponse(
            total_depth=total_depth,
            queues=queues,
            dead_letter_count=dead_letter_count,
        )

    except Exception as e:
        logger.error("Failed to get queue stats: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")


@router.get("/dead-letter", response_model=DeadLetterResponse)
async def get_dead_letter_messages(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    limit: int = 100,
):
    """
    Get messages from dead letter queue.

    Requires admin role.
    """
    try:
        redis = await get_redis_queue()

        # Read messages from dead letter stream
        messages = await redis.xrange("chad:logs:dead-letter", count=limit)

        result = []
        for msg_id, fields in messages:
            try:
                data = json.loads(fields.get("data", "{}"))
            except json.JSONDecodeError:
                data = {"raw": fields.get("data", "")}

            result.append(DeadLetterMessage(
                id=msg_id,
                original_stream=fields.get("original_stream", ""),
                original_id=fields.get("original_id", ""),
                data=data,
                reason=fields.get("reason", ""),
            ))

        count = await redis.xlen("chad:logs:dead-letter")

        return DeadLetterResponse(count=count, messages=result)

    except Exception as e:
        logger.error("Failed to get dead letter messages: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")


def _index_suffix_for_retry(fields: dict) -> str:
    """Resolve the index_suffix for re-injecting a dead-letter message.

    Newer DLQ entries carry index_suffix explicitly. Older ones (written before
    that field was added) fall back to the original stream suffix, since streams
    are keyed chad:logs:{index_suffix}.
    """
    suffix = fields.get("index_suffix")
    if suffix:
        return suffix
    return fields.get("original_stream", "").replace("chad:logs:", "") or "unknown"


@router.post("/dead-letter/retry")
async def retry_dead_letter(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Retry all messages in the dead letter queue.

    Re-injects each message into its original stream with a fresh ID (so the age
    check restarts), then removes it from the dead letter stream. Requires admin
    role.
    """
    try:
        redis = await get_redis_queue()

        messages = await redis.xrange("chad:logs:dead-letter")
        retried = 0
        for msg_id, fields in messages:
            original_stream = fields.get("original_stream")
            if not original_stream:
                continue
            await redis.xadd(
                original_stream,
                {
                    "data": fields.get("data", "{}"),
                    "index_suffix": _index_suffix_for_retry(fields),
                },
            )
            await redis.xdel("chad:logs:dead-letter", msg_id)
            retried += 1

        logger.info(
            "Dead letter queue retried (%d messages) by user %s",
            retried,
            current_user.email,
        )

        return {"status": "retried", "count": retried}

    except Exception as e:
        logger.error("Failed to retry dead letter queue: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")


@router.post("/dead-letter/{message_id}/retry")
async def retry_dead_letter_message(
    message_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Retry a specific message from the dead letter queue.

    Requires admin role.
    """
    try:
        redis = await get_redis_queue()

        messages = await redis.xrange(
            "chad:logs:dead-letter", min=message_id, max=message_id
        )
        if not messages:
            raise HTTPException(status_code=404, detail="Message not found")

        _, fields = messages[0]
        original_stream = fields.get("original_stream")
        if not original_stream:
            raise HTTPException(
                status_code=422, detail="Message has no original stream to retry to"
            )

        await redis.xadd(
            original_stream,
            {
                "data": fields.get("data", "{}"),
                "index_suffix": _index_suffix_for_retry(fields),
            },
        )
        await redis.xdel("chad:logs:dead-letter", message_id)

        return {"status": "retried", "message_id": message_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to retry dead letter message: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")


@router.delete("/dead-letter")
async def clear_dead_letter(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Clear all messages from dead letter queue.

    Requires admin role. This action cannot be undone.
    """
    try:
        redis = await get_redis_queue()

        # Delete the stream entirely
        await redis.delete("chad:logs:dead-letter")

        logger.info("Dead letter queue cleared by user %s", current_user.email)

        return {"status": "cleared"}

    except Exception as e:
        logger.error("Failed to clear dead letter queue: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")


@router.delete("/dead-letter/{message_id}")
async def delete_dead_letter_message(
    message_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    """
    Delete a specific message from dead letter queue.

    Requires admin role.
    """
    try:
        redis = await get_redis_queue()

        deleted = await redis.xdel("chad:logs:dead-letter", message_id)

        if deleted == 0:
            raise HTTPException(status_code=404, detail="Message not found")

        return {"status": "deleted", "message_id": message_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete dead letter message: %s", e)
        raise HTTPException(status_code=503, detail="Redis unavailable")
