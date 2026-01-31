"""Worker process for log queue processing."""

import asyncio
import json
import logging
import os
import signal
import sys
import time

from sqlalchemy import select

from app.core.redis import get_redis, close_redis
from app.services.log_processor import LogProcessor
from app.services.queue_settings import get_queue_settings
from app.services.opensearch import get_client_from_settings
from app.db.session import async_session_maker
from app.models.index_pattern import IndexPattern
from app.models.health_metrics import IndexHealthMetrics

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

    async def get_log_streams(self, redis) -> list[str]:
        """Get all log streams (excluding dead-letter)."""
        streams = []
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor, match="chad:logs:*", count=100)
            for key in keys:
                if "dead-letter" not in key:
                    streams.append(key)
            if cursor == 0:
                break
        return streams

    async def ensure_consumer_group(self, redis, streams: list[str]):
        """Create consumer group for given streams if it doesn't exist."""
        for stream in streams:
            try:
                await redis.xgroup_create(stream, CONSUMER_GROUP, id="0", mkstream=True)
                logger.info(f"Created consumer group for {stream}")
            except Exception as e:
                if "BUSYGROUP" not in str(e):
                    logger.warning(f"Failed to create group for {stream}: {e}")

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

        # Process each index's logs as a batch and record health metrics
        for index_suffix, log_entries in logs_by_index.items():
            logs = [entry[2] for entry in log_entries]
            result = None
            logs_errored = 0

            try:
                result = await processor.process_batch(db_session, index_suffix, logs)
            except Exception as e:
                logger.error(f"Failed to process batch for {index_suffix}: {e}")
                logs_errored = len(logs)
                # Still acknowledge to prevent reprocessing
                # In production, might want to move to dead letter instead

            # Mark as processed
            for stream, msg_id, _ in log_entries:
                processed.append((stream, msg_id))

            # Record health metrics for this batch
            try:
                await self._record_health_metrics(
                    db_session,
                    index_suffix,
                    logs_received=len(logs),
                    logs_errored=logs_errored,
                    alerts_created=result.get("alerts_created", 0) if result else 0,
                    matches=result.get("matches", 0) if result else 0,
                    elapsed_seconds=result.get("elapsed_seconds", 0) if result else 0,
                )
            except Exception as e:
                logger.warning(f"Failed to record health metrics for {index_suffix}: {e}")

        return processed

    async def _record_health_metrics(
        self,
        db_session,
        index_suffix: str,
        logs_received: int,
        logs_errored: int,
        alerts_created: int,
        matches: int,
        elapsed_seconds: float,
    ):
        """Record health metrics for an index pattern."""
        # Look up index pattern by suffix
        result = await db_session.execute(
            select(IndexPattern).where(IndexPattern.name == index_suffix)
        )
        index_pattern = result.scalar_one_or_none()

        if not index_pattern:
            logger.debug(f"No index pattern found for suffix '{index_suffix}', skipping metrics")
            return

        # Calculate average latency in ms (per log)
        avg_latency_ms = int((elapsed_seconds * 1000) / logs_received) if logs_received > 0 else 0

        # Get current queue depth
        redis = await get_redis()
        stream_key = f"chad:logs:{index_suffix}"
        try:
            queue_depth = await redis.xlen(stream_key)
        except Exception:
            queue_depth = 0

        metric = IndexHealthMetrics(
            index_pattern_id=index_pattern.id,
            logs_received=logs_received,
            logs_processed=logs_received - logs_errored,
            logs_errored=logs_errored,
            alerts_generated=alerts_created,
            rules_triggered=matches,
            queue_depth=queue_depth,
            avg_detection_latency_ms=avg_latency_ms,
        )
        db_session.add(metric)
        await db_session.commit()

    async def claim_pending_messages(self, redis, streams: list[str]) -> list:
        """
        Claim pending messages that have been idle too long.

        This handles messages that were delivered to crashed/restarted workers.
        """
        claimed_messages = []
        min_idle_time = 30000  # 30 seconds - reclaim if idle this long

        for stream in streams:
            try:
                # XAUTOCLAIM: claim messages idle > min_idle_time
                # Returns: [next_start_id, [[msg_id, {fields}], ...], [deleted_ids]]
                result = await redis.xautoclaim(
                    stream,
                    CONSUMER_GROUP,
                    self.consumer_name,
                    min_idle_time,
                    start_id="0-0",
                    count=100,
                )

                if result and len(result) > 1 and result[1]:
                    # result[1] contains the claimed messages
                    messages = result[1]
                    if messages:
                        claimed_messages.append((stream, messages))
                        logger.info(f"Claimed {len(messages)} pending messages from {stream}")

            except Exception as e:
                # XAUTOCLAIM may not exist in older Redis versions
                if "unknown command" in str(e).lower():
                    logger.debug(f"XAUTOCLAIM not available, skipping pending claim")
                else:
                    logger.warning(f"Failed to claim pending from {stream}: {e}")

        return claimed_messages

    async def trim_processed_messages(self, redis, stream: str, last_id: str):
        """
        Trim messages from stream that have been fully processed.

        This removes ACKed messages to prevent unbounded stream growth.
        """
        try:
            # XTRIM with MINID removes all messages with ID < minid
            # This is safe because we only call this after successful ACK
            deleted = await redis.xtrim(stream, minid=last_id, approximate=False)
            if deleted > 0:
                logger.debug(f"Trimmed {deleted} processed messages from {stream}")
        except Exception as e:
            logger.warning(f"Failed to trim {stream}: {e}")

    async def run(self):
        """Main worker loop."""
        logger.info(f"Worker {self.consumer_name} starting")

        redis = await get_redis()

        # Get OpenSearch client from database settings
        async with async_session_maker() as db_session:
            os_client = await get_client_from_settings(db_session)

        if os_client is None:
            logger.error("OpenSearch not configured, worker exiting")
            return

        processor = LogProcessor(os_client, async_session_maker)

        logger.info(f"Worker {self.consumer_name} ready, waiting for messages")

        claim_interval = 0  # Counter for periodic pending claim

        while self.running:
            try:
                # Get current streams
                streams = await self.get_log_streams(redis)

                if not streams:
                    # No streams yet, wait and retry
                    await asyncio.sleep(5)
                    continue

                # Ensure consumer groups exist for all streams
                await self.ensure_consumer_group(redis, streams)

                messages = []

                # Periodically check for and claim pending messages (every 10 iterations)
                claim_interval += 1
                if claim_interval >= 10:
                    claim_interval = 0
                    claimed = await self.claim_pending_messages(redis, streams)
                    if claimed:
                        messages = claimed

                # If no claimed messages, read new ones
                if not messages:
                    # Build stream dict for xreadgroup
                    stream_dict = {stream: ">" for stream in streams}

                    # Read from all streams
                    messages = await redis.xreadgroup(
                        CONSUMER_GROUP,
                        self.consumer_name,
                        stream_dict,
                        count=500,  # Batch size
                        block=5000,  # 5 second timeout
                    )

                if not messages:
                    continue

                self.processing = True

                # Track the highest processed message ID per stream for trimming
                max_ids_per_stream: dict[str, str] = {}

                async with async_session_maker() as db_session:
                    processed = await self.process_batch(processor, messages, db_session)

                # Acknowledge and track max IDs for trimming
                for stream, msg_id in processed:
                    await redis.xack(stream, CONSUMER_GROUP, msg_id)
                    # Track highest ID per stream
                    if stream not in max_ids_per_stream or msg_id > max_ids_per_stream[stream]:
                        max_ids_per_stream[stream] = msg_id

                # Trim processed messages from each stream
                for stream, max_id in max_ids_per_stream.items():
                    await self.trim_processed_messages(redis, stream, max_id)

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
