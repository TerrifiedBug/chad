"""Log queue service for Redis Streams."""

import json
import logging

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class LogQueueService:
    """Service for enqueueing logs to Redis Streams."""

    STREAM_PREFIX = "chad:logs:"
    DEAD_LETTER_STREAM = "chad:logs:dead-letter"

    def __init__(self, redis: Redis, max_queue_size: int = 100000):
        """
        Initialize log queue service.

        Args:
            redis: Redis client instance
            max_queue_size: Maximum messages in stream (oldest evicted when exceeded)
        """
        self.redis = redis
        self.max_queue_size = max_queue_size

    def _stream_name(self, index_suffix: str) -> str:
        """Get stream name for an index suffix."""
        return f"{self.STREAM_PREFIX}{index_suffix}"

    async def enqueue_logs(
        self,
        index_suffix: str,
        logs: list[dict],
    ) -> dict:
        """
        Enqueue logs to Redis stream for async processing.

        Args:
            index_suffix: The index pattern suffix (e.g., "windows")
            logs: List of log documents

        Returns:
            Dict with queued count and current queue depth
        """
        stream_name = self._stream_name(index_suffix)

        for log in logs:
            await self.redis.xadd(
                stream_name,
                {
                    "data": json.dumps(log),
                    "index_suffix": index_suffix,
                },
                maxlen=self.max_queue_size,
            )

        queue_depth = await self.redis.xlen(stream_name)

        return {
            "queued": len(logs),
            "queue_depth": queue_depth,
        }

    async def get_queue_depth(self, index_suffix: str) -> int:
        """Get current queue depth for an index."""
        return await self.redis.xlen(self._stream_name(index_suffix))

    async def get_total_queue_depth(self) -> int:
        """Get total queue depth across all streams."""
        total = 0
        cursor = 0

        while True:
            cursor, keys = await self.redis.scan(
                cursor, match=f"{self.STREAM_PREFIX}*", count=100
            )
            for key in keys:
                if key != self.DEAD_LETTER_STREAM:
                    total += await self.redis.xlen(key)
            if cursor == 0:
                break

        return total

    async def move_to_dead_letter(
        self,
        stream_name: str,
        message_id: str,
        message_data: dict,
        reason: str,
    ) -> None:
        """Move a message to the dead letter queue."""
        await self.redis.xadd(
            self.DEAD_LETTER_STREAM,
            {
                "original_stream": stream_name,
                "original_id": message_id,
                "data": json.dumps(message_data),
                "reason": reason,
            },
        )
        logger.warning(f"Message {message_id} moved to dead-letter: {reason}")
