"""Worker process for log queue processing."""

import asyncio
import json
import logging
import os
import signal
import sys
import time

from app.core.redis import get_redis, close_redis
from app.services.log_processor import LogProcessor
from app.services.queue_settings import get_queue_settings
from app.api.deps import get_opensearch_client
from app.db.session import async_session_maker

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "chad-workers"


class Worker:
    """Worker that processes logs from Redis Streams."""

    def __init__(self):
        self.running = True
        self.processing = False
        self.shutdown_timeout = 60
        self.consumer_name = f"worker-{os.getpid()}"

    def shutdown(self):
        """Signal graceful shutdown."""
        logger.info("Shutdown signal received")
        self.running = False

    async def ensure_consumer_group(self, redis, stream_pattern: str):
        """Create consumer group if it doesn't exist."""
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor, match=stream_pattern, count=100)
            for key in keys:
                try:
                    await redis.xgroup_create(key, CONSUMER_GROUP, id="0", mkstream=True)
                    logger.info(f"Created consumer group for {key}")
                except Exception as e:
                    if "BUSYGROUP" not in str(e):
                        logger.warning(f"Failed to create group for {key}: {e}")
            if cursor == 0:
                break

    async def process_batch(
        self,
        processor: LogProcessor,
        messages: list,
        db_session,
    ) -> list[tuple[str, str]]:
        """
        Process a batch of messages.

        Returns list of (stream, message_id) tuples for acknowledgment.
        """
        processed = []

        # Get queue settings for TTL check
        queue_settings = await get_queue_settings(db_session)

        # Group messages by index_suffix for batch processing
        logs_by_index: dict[str, list[tuple[str, str, dict]]] = {}

        for stream, entries in messages:
            for msg_id, fields in entries:
                # Check message age (TTL)
                msg_timestamp = int(msg_id.split("-")[0])
                age_seconds = (time.time() * 1000 - msg_timestamp) / 1000

                if age_seconds > queue_settings.message_ttl_seconds:
                    # Move to dead letter
                    redis = await get_redis()
                    await redis.xadd(
                        "chad:logs:dead-letter",
                        {
                            "original_stream": stream,
                            "original_id": msg_id,
                            "data": fields.get("data", "{}"),
                            "reason": f"TTL exceeded ({age_seconds:.0f}s > {queue_settings.message_ttl_seconds}s)",
                        },
                    )
                    processed.append((stream, msg_id))
                    continue

                index_suffix = fields.get("index_suffix", "unknown")
                log_data = json.loads(fields.get("data", "{}"))

                if index_suffix not in logs_by_index:
                    logs_by_index[index_suffix] = []
                logs_by_index[index_suffix].append((stream, msg_id, log_data))

        # Process each index's logs as a batch
        for index_suffix, log_entries in logs_by_index.items():
            logs = [entry[2] for entry in log_entries]

            try:
                await processor.process_batch(index_suffix, logs)
            except Exception as e:
                logger.error(f"Failed to process batch for {index_suffix}: {e}")
                # Still acknowledge to prevent reprocessing
                # In production, might want to move to dead letter instead

            # Mark as processed
            for stream, msg_id, _ in log_entries:
                processed.append((stream, msg_id))

        return processed

    async def run(self):
        """Main worker loop."""
        logger.info(f"Worker {self.consumer_name} starting")

        redis = await get_redis()
        os_client = get_opensearch_client()

        if os_client is None:
            logger.error("OpenSearch not configured, worker exiting")
            return

        processor = LogProcessor(os_client, async_session_maker)

        # Ensure consumer groups exist
        await self.ensure_consumer_group(redis, "chad:logs:*")

        while self.running:
            try:
                # Read from all streams
                messages = await redis.xreadgroup(
                    CONSUMER_GROUP,
                    self.consumer_name,
                    {"chad:logs:*": ">"},
                    count=500,  # Batch size - will be configurable
                    block=5000,  # 5 second timeout
                )

                if not messages:
                    continue

                self.processing = True

                async with async_session_maker() as db_session:
                    processed = await self.process_batch(processor, messages, db_session)

                # Acknowledge processed messages
                for stream, msg_id in processed:
                    await redis.xack(stream, CONSUMER_GROUP, msg_id)

                self.processing = False

            except Exception as e:
                logger.error(f"Worker error: {e}")
                self.processing = False
                await asyncio.sleep(1)  # Back off on error

        logger.info(f"Worker {self.consumer_name} shutting down")
        await close_redis()


def main():
    """Entry point for worker process."""
    from app.core.logging import setup_logging
    setup_logging()

    worker = Worker()

    # Handle shutdown signals
    def handle_signal(signum, frame):
        worker.shutdown()

        # Wait for current batch
        deadline = time.time() + worker.shutdown_timeout
        while worker.processing and time.time() < deadline:
            time.sleep(0.1)

        if worker.processing:
            logger.warning("Shutdown timeout, force exiting")

        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
