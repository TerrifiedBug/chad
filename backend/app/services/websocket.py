"""
WebSocket connection manager for real-time alert broadcasting.

Manages active WebSocket connections and broadcasts alerts to connected clients.
Uses Redis pub/sub for cross-worker broadcasting in multi-worker deployments.
"""

import logging

from fastapi import WebSocket
from pydantic import BaseModel

from app.services.alert_pubsub import AlertSubscriber, publish_alert

logger = logging.getLogger(__name__)


class AlertBroadcast(BaseModel):
    """Alert data for WebSocket broadcasting."""
    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    timestamp: str
    matched_log: dict


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts messages.

    This class maintains active connections for the current worker process
    and uses Redis pub/sub to receive alerts from other workers.
    """

    def __init__(self):
        # Store active connections by user ID
        self.active_connections: dict[str, list[WebSocket]] = {}
        # Store all active connections for debugging
        self._all_connections: set[WebSocket] = set()
        # Redis subscriber for cross-worker broadcasts
        self._subscriber: AlertSubscriber | None = None

    async def start_subscriber(self):
        """Start the Redis pub/sub subscriber for cross-worker broadcasts."""
        if self._subscriber is not None:
            return

        self._subscriber = AlertSubscriber(self._on_redis_alert)
        await self._subscriber.start()
        logger.info("WebSocket manager started Redis pub/sub subscriber")

    async def stop_subscriber(self):
        """Stop the Redis pub/sub subscriber."""
        if self._subscriber:
            await self._subscriber.stop()
            self._subscriber = None
            logger.info("WebSocket manager stopped Redis pub/sub subscriber")

    async def _on_redis_alert(self, alert_data: dict):
        """
        Callback for alerts received from Redis pub/sub.

        Broadcasts the alert to all local WebSocket connections.
        """
        if not self._all_connections:
            return

        message = {
            "type": "alert",
            "data": alert_data,
        }
        await self.broadcast_to_all_local(message)

    async def connect(self, websocket: WebSocket, user_id: str):
        """
        Register a new WebSocket connection.

        Note: The WebSocket should already be accepted before calling this method.

        Args:
            websocket: The WebSocket connection
            user_id: The user ID for this connection
        """
        self._all_connections.add(websocket)

        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

        logger.info(f"WebSocket connected for user {user_id}. Total connections: {len(self._all_connections)}")

    def disconnect(self, websocket: WebSocket, user_id: str):
        """
        Remove and close a WebSocket connection.

        Args:
            websocket: The WebSocket connection
            user_id: The user ID for this connection
        """
        self._all_connections.discard(websocket)

        if user_id in self.active_connections:
            self.active_connections[user_id] = [
                conn for conn in self.active_connections[user_id] if conn != websocket
            ]
            # Clean up empty user lists
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

        logger.info(f"WebSocket disconnected for user {user_id}. Total connections: {len(self._all_connections)}")

    async def broadcast_to_user(self, user_id: str, message: dict):
        """
        Broadcast a message to all connections for a specific user.

        Args:
            user_id: The user ID to broadcast to
            message: The message to broadcast (will be JSON serialized)
        """
        if user_id not in self.active_connections:
            return

        # Remove disconnected clients
        self.active_connections[user_id] = [
            conn for conn in self.active_connections[user_id]
            if conn in self._all_connections
        ]

        # Clean up if no connections remain
        if not self.active_connections[user_id]:
            del self.active_connections[user_id]
            return

        # Broadcast to all connections for this user
        disconnected = []
        for connection in self.active_connections[user_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send WebSocket message: {e}")
                disconnected.append(connection)

        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn, user_id)

    async def broadcast_to_all_local(self, message: dict):
        """
        Broadcast a message to all local connections (this worker only).

        Args:
            message: The message to broadcast (will be JSON serialized)
        """
        if not self._all_connections:
            return

        disconnected = []
        for connection in list(self._all_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send WebSocket message: {e}")
                disconnected.append(connection)

        # Clean up disconnected connections
        for conn in disconnected:
            self._all_connections.discard(conn)
            # Also remove from user-specific lists
            for user_id in list(self.active_connections.keys()):
                if conn in self.active_connections.get(user_id, []):
                    self.disconnect(conn, user_id)
                    break

    async def broadcast_to_all(self, message: dict):
        """
        Broadcast a message to all connections across all workers.

        Uses Redis pub/sub for cross-worker broadcasting.

        Args:
            message: The message to broadcast (will be JSON serialized)
        """
        # Publish to Redis for other workers
        if message.get("type") == "alert" and message.get("data"):
            await publish_alert(message["data"])

        # Also broadcast locally (in case pub/sub hasn't delivered yet)
        await self.broadcast_to_all_local(message)

    async def broadcast_alert(self, alert: AlertBroadcast, user_id: str | None = None):
        """
        Broadcast an alert to WebSocket clients.

        Args:
            alert: The alert to broadcast
            user_id: If specified, only broadcast to this user's connections.
                     If None, broadcast to all connections.
        """
        message = {
            "type": "alert",
            "data": alert.model_dump(),
        }

        if user_id:
            await self.broadcast_to_user(user_id, message)
        else:
            await self.broadcast_to_all(message)

    async def broadcast_alert_dict(self, alert_data: dict):
        """
        Broadcast an alert dict to all WebSocket clients across all workers.

        This is used by the worker to broadcast alerts via Redis pub/sub.

        Args:
            alert_data: Alert data dictionary
        """
        # Publish to Redis for cross-worker broadcast
        await publish_alert(alert_data)

        # Also broadcast locally
        message = {
            "type": "alert",
            "data": alert_data,
        }
        await self.broadcast_to_all_local(message)

    def get_connection_count(self) -> int:
        """Get the total number of active connections."""
        return len(self._all_connections)

    def get_user_connection_count(self, user_id: str) -> int:
        """Get the number of active connections for a specific user."""
        return len(self.active_connections.get(user_id, []))


# Global connection manager instance
manager = ConnectionManager()
