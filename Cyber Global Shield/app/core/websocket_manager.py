"""
Cyber Global Shield — WebSocket Manager for Real-Time Notifications
Push alerts, SOAR updates, ML detections, and system events to connected clients.
"""

import json
import asyncio
import uuid
from typing import Dict, Set, Optional, Any, Callable
from datetime import datetime, timezone
from enum import Enum

import structlog
from fastapi import WebSocket, WebSocketDisconnect

logger = structlog.get_logger(__name__)


# =============================================================================
# Event Types
# =============================================================================

class EventType(str, Enum):
    """Types of events that can be pushed via WebSocket."""
    ALERT_CRITICAL = "alert.critical"
    ALERT_HIGH = "alert.high"
    ALERT_UPDATE = "alert.update"
    SOAR_STARTED = "soar.started"
    SOAR_COMPLETED = "soar.completed"
    SOAR_FAILED = "soar.failed"
    SOAR_PROGRESS = "soar.progress"
    ML_ANOMALY = "ml.anomaly"
    ML_TRAINING_COMPLETE = "ml.training_complete"
    FL_ROUND_COMPLETE = "fl.round_complete"
    FL_CLIENT_CONNECTED = "fl.client_connected"
    SYSTEM_HEALTH = "system.health"
    SYSTEM_ERROR = "system.error"
    PIPELINE_STATUS = "pipeline.status"
    THREAT_INTEL_UPDATE = "threat_intel.update"
    USER_NOTIFICATION = "user.notification"


# =============================================================================
# WebSocket Connection Manager
# =============================================================================

class ConnectionManager:
    """
    Manages WebSocket connections with channel-based subscriptions.
    Supports org-level and user-level channels.
    """

    def __init__(self):
        # {connection_id: WebSocket}
        self._connections: Dict[str, WebSocket] = {}
        # {channel: set(connection_ids)}
        self._channels: Dict[str, Set[str]] = {
            "broadcast": set(),
            "alerts": set(),
            "soar": set(),
            "ml": set(),
            "fl": set(),
            "system": set(),
        }
        # {connection_id: set(channels)}
        self._connection_channels: Dict[str, Set[str]] = {}
        # {org_id: set(connection_ids)}
        self._org_channels: Dict[str, Set[str]] = {}
        # Event history for late-joining clients (last 100 events)
        self._event_history: list = []
        self._max_history = 100
        # Stats
        self._total_connections = 0
        self._total_messages_sent = 0

    async def connect(
        self,
        websocket: WebSocket,
        org_id: str = "default",
        user_id: Optional[str] = None,
        channels: Optional[list[str]] = None,
    ) -> str:
        """
        Accept a new WebSocket connection and subscribe to channels.
        Returns connection_id.
        """
        await websocket.accept()

        connection_id = str(uuid.uuid4())
        self._connections[connection_id] = websocket
        self._total_connections += 1

        # Subscribe to broadcast channel by default
        self._channels["broadcast"].add(connection_id)
        self._connection_channels[connection_id] = {"broadcast"}

        # Subscribe to specified channels
        if channels:
            for channel in channels:
                if channel in self._channels:
                    self._channels[channel].add(connection_id)
                    self._connection_channels[connection_id].add(channel)

        # Subscribe to org channel
        if org_id not in self._org_channels:
            self._org_channels[org_id] = set()
        self._org_channels[org_id].add(connection_id)

        logger.info(
            "websocket_connected",
            connection_id=connection_id[:8],
            org_id=org_id,
            user_id=user_id,
            channels=channels,
            total_connections=len(self._connections),
        )

        # Send recent event history to new client
        if self._event_history:
            await self.send_personal_message(
                connection_id,
                {
                    "type": "system.history",
                    "data": {"events": self._event_history[-20:]},  # Last 20 events
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

        # Send welcome message
        await self.send_personal_message(
            connection_id,
            {
                "type": "system.connected",
                "data": {
                    "connection_id": connection_id[:8],
                    "org_id": org_id,
                    "channels": list(self._connection_channels[connection_id]),
                    "server_time": datetime.now(timezone.utc).isoformat(),
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        return connection_id

    async def disconnect(self, connection_id: str):
        """Remove a WebSocket connection."""
        if connection_id in self._connections:
            del self._connections[connection_id]

            # Remove from all channels
            channels = self._connection_channels.pop(connection_id, set())
            for channel in channels:
                if channel in self._channels:
                    self._channels[channel].discard(connection_id)

            # Remove from org channels
            for org_id in list(self._org_channels.keys()):
                self._org_channels[org_id].discard(connection_id)
                if not self._org_channels[org_id]:
                    del self._org_channels[org_id]

            logger.info(
                "websocket_disconnected",
                connection_id=connection_id[:8],
                total_connections=len(self._connections),
            )

    async def send_personal_message(self, connection_id: str, message: dict):
        """Send a message to a specific connection."""
        websocket = self._connections.get(connection_id)
        if websocket:
            try:
                await websocket.send_json(message)
                self._total_messages_sent += 1
            except Exception as e:
                logger.warning(
                    "websocket_send_failed",
                    connection_id=connection_id[:8],
                    error=str(e),
                )
                await self.disconnect(connection_id)

    async def broadcast(self, message: dict, channel: str = "broadcast"):
        """Broadcast a message to all connections in a channel."""
        # Add timestamp if not present
        if "timestamp" not in message:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Store in event history
        self._event_history.append(message)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        # Send to channel subscribers
        connection_ids = self._channels.get(channel, set()).copy()
        tasks = []
        for cid in connection_ids:
            tasks.append(self.send_personal_message(cid, message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_to_org(self, org_id: str, message: dict):
        """Broadcast a message to all connections in an organization."""
        connection_ids = self._org_channels.get(org_id, set()).copy()
        tasks = []
        for cid in connection_ids:
            tasks.append(self.send_personal_message(cid, message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def subscribe_to_channel(self, connection_id: str, channel: str):
        """Subscribe a connection to a channel."""
        if channel in self._channels:
            self._channels[channel].add(connection_id)
            if connection_id in self._connection_channels:
                self._connection_channels[connection_id].add(channel)

    async def unsubscribe_from_channel(self, connection_id: str, channel: str):
        """Unsubscribe a connection from a channel."""
        if channel in self._channels:
            self._channels[channel].discard(connection_id)
            if connection_id in self._connection_channels:
                self._connection_channels[connection_id].discard(channel)

    def get_stats(self) -> dict:
        """Get connection manager statistics."""
        return {
            "total_connections": len(self._connections),
            "total_messages_sent": self._total_messages_sent,
            "total_connections_ever": self._total_connections,
            "channels": {k: len(v) for k, v in self._channels.items()},
            "orgs": {k: len(v) for k, v in self._org_channels.items()},
            "event_history_size": len(self._event_history),
        }

    async def health_check(self) -> dict:
        """Health check for the WebSocket manager."""
        return {
            "status": "healthy" if len(self._connections) >= 0 else "degraded",
            "active_connections": len(self._connections),
            "active_channels": sum(1 for v in self._channels.values() if v),
            "active_orgs": len(self._org_channels),
        }


# Global WebSocket manager instance
ws_manager = ConnectionManager()


# =============================================================================
# Event Emitter Functions
# =============================================================================

async def emit_alert(alert: dict):
    """Emit an alert event to all connected clients."""
    severity = alert.get("severity", "info").lower()
    event_type = EventType.ALERT_CRITICAL if severity == "critical" else EventType.ALERT_HIGH

    message = {
        "type": event_type,
        "data": {
            "id": alert.get("id"),
            "event_type": alert.get("event_type"),
            "severity": severity,
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "title": alert.get("title", f"Alert: {alert.get('event_type', 'unknown')}"),
            "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        },
    }

    # Broadcast to alerts channel and org
    await ws_manager.broadcast(message, channel="alerts")
    org_id = alert.get("org_id", "default")
    await ws_manager.broadcast_to_org(org_id, message)


async def emit_soar_progress(execution_id: str, playbook_name: str, status: str, progress: float = 0, action: Optional[dict] = None):
    """Emit SOAR playbook execution progress."""
    message = {
        "type": EventType.SOAR_PROGRESS,
        "data": {
            "execution_id": execution_id,
            "playbook_name": playbook_name,
            "status": status,
            "progress": progress,
            "current_action": action,
        },
    }
    await ws_manager.broadcast(message, channel="soar")


async def emit_soar_completed(execution_id: str, playbook_name: str, status: str, duration_ms: float):
    """Emit SOAR playbook completion."""
    event_type = EventType.SOAR_COMPLETED if status == "completed" else EventType.SOAR_FAILED
    message = {
        "type": event_type,
        "data": {
            "execution_id": execution_id,
            "playbook_name": playbook_name,
            "status": status,
            "duration_ms": duration_ms,
        },
    }
    await ws_manager.broadcast(message, channel="soar")


async def emit_ml_anomaly(anomaly_score: float, is_anomaly: bool, explanation: str, log_source: str = "unknown"):
    """Emit ML anomaly detection result."""
    if is_anomaly:
        message = {
            "type": EventType.ML_ANOMALY,
            "data": {
                "anomaly_score": anomaly_score,
                "is_anomaly": is_anomaly,
                "explanation": explanation,
                "source": log_source,
            },
        }
        await ws_manager.broadcast(message, channel="ml")


async def emit_fl_round_complete(round_num: int, total_rounds: int, loss: float, clients: int):
    """Emit federated learning round completion."""
    message = {
        "type": EventType.FL_ROUND_COMPLETE,
        "data": {
            "round": round_num,
            "total_rounds": total_rounds,
            "loss": loss,
            "clients": clients,
        },
    }
    await ws_manager.broadcast(message, channel="fl")


async def emit_system_notification(title: str, message_text: str, level: str = "info"):
    """Emit a system notification."""
    message = {
        "type": EventType.USER_NOTIFICATION,
        "data": {
            "title": title,
            "message": message_text,
            "level": level,
        },
    }
    await ws_manager.broadcast(message, channel="system")


# =============================================================================
# FastAPI WebSocket Endpoint Handler
# =============================================================================

async def websocket_endpoint(websocket: WebSocket, org_id: str = "default"):
    """
    WebSocket endpoint handler.
    Connect to: ws://localhost:8000/ws?org_id=default
    """
    connection_id = await ws_manager.connect(
        websocket=websocket,
        org_id=org_id,
        channels=["alerts", "soar", "ml", "fl", "system"],
    )

    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                action = message.get("action")

                if action == "subscribe":
                    channel = message.get("channel")
                    if channel:
                        await ws_manager.subscribe_to_channel(connection_id, channel)
                        await ws_manager.send_personal_message(
                            connection_id,
                            {
                                "type": "system.subscribed",
                                "data": {"channel": channel},
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            },
                        )

                elif action == "unsubscribe":
                    channel = message.get("channel")
                    if channel:
                        await ws_manager.unsubscribe_from_channel(connection_id, channel)
                        await ws_manager.send_personal_message(
                            connection_id,
                            {
                                "type": "system.unsubscribed",
                                "data": {"channel": channel},
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            },
                        )

                elif action == "ping":
                    await ws_manager.send_personal_message(
                        connection_id,
                        {
                            "type": "system.pong",
                            "data": {"server_time": datetime.now(timezone.utc).isoformat()},
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

                elif action == "get_stats":
                    await ws_manager.send_personal_message(
                        connection_id,
                        {
                            "type": "system.stats",
                            "data": ws_manager.get_stats(),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

            except json.JSONDecodeError:
                await ws_manager.send_personal_message(
                    connection_id,
                    {
                        "type": "system.error",
                        "data": {"message": "Invalid JSON"},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

    except WebSocketDisconnect:
        await ws_manager.disconnect(connection_id)
    except Exception as e:
        logger.error("websocket_error", connection_id=connection_id[:8], error=str(e))
        await ws_manager.disconnect(connection_id)
