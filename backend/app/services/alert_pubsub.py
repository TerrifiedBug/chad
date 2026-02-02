"""
Redis pub/sub service for cross-worker alert broadcasting.

Enables WebSocket connections on any worker to receive alerts
created by any other worker.
"""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

from app.core.redis import get_redis

logger = logging.getLogger(__name__)

# Redis channel for alert broadcasts
ALERT_CHANNEL = "chad:alerts:broadcast"


async def publish_alert(alert_data: dict) -> bool:
    """
    Publish an alert to the Redis pub/sub channel.

    Args:
        alert_data: Alert data to broadcast (will be JSON serialized)

    Returns:
        True if published successfully, False otherwise
    """
    try:
        redis = await get_redis()
        message = json.dumps(alert_data)
        await redis.publish(ALERT_CHANNEL, message)
        logger.debug(f"Published alert to channel: {alert_data.get('alert_id', 'unknown')}")
        return True
    except Exception as e:
        logger.warning(f"Failed to publish alert: {e}")
        return False


class AlertSubscriber:
    """
    Subscribes to the Redis alert channel and calls a callback for each message.

    Usage:
        subscriber = AlertSubscriber(on_alert_callback)
        await subscriber.start()
        # ... later
        await subscriber.stop()
    """

    def __init__(self, callback: Callable[[dict], Awaitable[None]]):
        """
        Initialize the subscriber.

        Args:
            callback: Async function to call for each received alert
        """
        self.callback = callback
        self._running = False
        self._task: asyncio.Task | None = None
        self._pubsub = None

    async def start(self):
        """Start listening for alerts."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._listen())
        logger.debug("Alert subscriber started")

    async def stop(self):
        """Stop listening for alerts."""
        self._running = False

        if self._pubsub:
            try:
                await self._pubsub.unsubscribe(ALERT_CHANNEL)
                await self._pubsub.close()
            except Exception as e:
                # Ignore errors during cleanup - connection may already be closed
                logger.debug("Error during pubsub cleanup: %s", e)
            self._pubsub = None

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                # Expected when cancelling the task - no action needed
                pass
            self._task = None

        logger.debug("Alert subscriber stopped")

    async def _listen(self):
        """Main listening loop."""
        try:
            redis = await get_redis()
            self._pubsub = redis.pubsub()
            await self._pubsub.subscribe(ALERT_CHANNEL)

            while self._running:
                try:
                    message = await self._pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )

                    if message and message.get("type") == "message":
                        data = message.get("data")
                        if data:
                            try:
                                if isinstance(data, bytes):
                                    data = data.decode("utf-8")
                                alert_data = json.loads(data)
                                await self.callback(alert_data)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in alert message: {e}")
                            except Exception as e:
                                logger.warning(f"Error processing alert message: {e}")

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning(f"Error in alert subscriber: {e}")
                    await asyncio.sleep(1)  # Back off on error

        except Exception as e:
            logger.error(f"Alert subscriber failed: {e}")
        finally:
            self._running = False
