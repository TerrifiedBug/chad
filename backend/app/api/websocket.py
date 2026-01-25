"""
WebSocket API endpoint for real-time alert streaming.

Clients can connect to this endpoint to receive real-time alerts
as they are created.
"""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_websocket, get_db
from app.models.user import User
from app.services.websocket import manager

router = APIRouter(prefix="/ws", tags=["websocket"])
logger = logging.getLogger(__name__)


@router.websocket("/alerts")
async def websocket_alerts(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
):
    """
    WebSocket endpoint for real-time alert streaming.

    Clients connect to this endpoint to receive alerts in real-time.
    The connection is authenticated via JWT token in the query parameter.

    Query parameters:
        token: JWT authentication token

    Message format:
        {
            "type": "alert",
            "data": {
                "alert_id": "...",
                "rule_id": "...",
                "rule_title": "...",
                "severity": "...",
                "timestamp": "...",
                "matched_log": {...}
            }
        }
    """
    # Authenticate the WebSocket connection
    user = await get_current_user_websocket(websocket, db)
    if not user:
        await websocket.close(code=1008, reason="Authentication failed")
        return

    # Accept the connection and register with the manager
    await manager.connect(websocket, str(user.id))

    try:
        # Keep the connection alive and handle incoming messages
        while True:
            # Wait for messages from client (for now we just echo ping/pong)
            data = await websocket.receive_text()

            # Handle ping/pong for keepalive
            if data == "ping":
                await websocket.send_text("pong")
            else:
                logger.debug(f"Received WebSocket message: {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket, str(user.id))
        logger.info(f"WebSocket disconnected for user {user.username}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user.username}: {e}")
        manager.disconnect(websocket, str(user.id))
