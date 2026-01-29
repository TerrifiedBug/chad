"""
WebSocket API endpoint for real-time alert streaming.

Clients can connect to this endpoint to receive real-time alerts
as they are created.
"""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import create_token_with_dynamic_timeout
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

    Authentication via Sec-WebSocket-Protocol header with Bearer token.
    Format: "Bearer, <jwt_token>"

    For backward compatibility, also accepts token via query parameter.

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
    # Log connection attempt
    client_host = websocket.client
    logger.info(f"WebSocket connection attempt from {client_host}")

    # Authenticate the WebSocket connection BEFORE accepting
    user = await get_current_user_websocket(websocket, db)
    if not user:
        logger.warning(f"WebSocket authentication failed from {client_host}")
        await websocket.close(code=1008, reason="Authentication failed")
        return

    logger.info(f"WebSocket authenticated for user {user.email} ({user.id})")

    # Accept the connection and register with the manager
    # Must accept before sending messages
    await websocket.accept(subprotocol='Bearer')
    await manager.connect(websocket, str(user.id))

    try:
        # Send a welcome message
        await websocket.send_json({"type": "connected", "message": "WebSocket connected successfully"})

        # Keep the connection alive and handle incoming messages
        while True:
            # Wait for messages from client (for now we just echo ping/pong)
            data = await websocket.receive_text()

            # Handle ping/pong for keepalive
            if data == "ping":
                # Extend the user's session by issuing a new token
                # This prevents session timeout while actively viewing live alerts
                try:
                    new_token = await create_token_with_dynamic_timeout(
                        str(user.id), db, user.token_version
                    )
                    await websocket.send_json({
                        "type": "pong",
                        "token": new_token,
                    })
                except Exception as e:
                    logger.warning(f"Failed to refresh token for {user.email}: {e}")
                    # Still send pong even if token refresh fails
                    await websocket.send_json({"type": "pong"})
            else:
                logger.debug(f"Received WebSocket message from {user.username}: {data}")

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for user {user.email}")
        manager.disconnect(websocket, str(user.id))
    except Exception as e:
        logger.error(f"WebSocket error for user {user.email}: {e}", exc_info=True)
        manager.disconnect(websocket, str(user.id))
