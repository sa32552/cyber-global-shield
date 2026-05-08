"""
Cyber Global Shield — Système de Notifications
Notifications sonores, visuelles, push, email, SMS pour les alertes SOC.
"""

import asyncio
import logging
from enum import Enum
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class NotificationSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class NotificationChannel(str, Enum):
    SOUND = "sound"
    VISUAL = "visual"
    PUSH = "push"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    WEBSOCKET = "websocket"


class Notification(BaseModel):
    """Standard notification model."""
    id: str
    title: str
    message: str
    severity: NotificationSeverity
    channels: List[NotificationChannel]
    source: str  # "ml", "soar", "system", "user"
    source_id: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime = datetime.utcnow()
    read: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


# Sound notification configuration
SOUND_CONFIG = {
    NotificationSeverity.INFO: {
        "file": "/static/sounds/info.mp3",
        "duration_ms": 1000,
        "loop": False,
        "volume": 0.3,
    },
    NotificationSeverity.WARNING: {
        "file": "/static/sounds/warning.mp3",
        "duration_ms": 2000,
        "loop": False,
        "volume": 0.5,
    },
    NotificationSeverity.CRITICAL: {
        "file": "/static/sounds/critical.mp3",
        "duration_ms": 5000,
        "loop": True,
        "volume": 0.8,
    },
    NotificationSeverity.EMERGENCY: {
        "file": "/static/sounds/emergency.mp3",
        "duration_ms": 10000,
        "loop": True,
        "volume": 1.0,
    },
}


class NotificationManager:
    """
    Centralized notification manager.
    Supports sound, visual, push, email, SMS, webhook, and WebSocket channels.
    """

    def __init__(self):
        self._handlers: Dict[NotificationChannel, List[Callable]] = {
            channel: [] for channel in NotificationChannel
        }
        self._history: List[Notification] = []
        self._max_history = 1000
        self._sound_enabled = True
        self._push_enabled = True

    def register_handler(self, channel: NotificationChannel, handler: Callable):
        """Register a handler for a notification channel."""
        self._handlers[channel].append(handler)
        logger.info(f"Handler registered for channel: {channel}")

    async def send(
        self,
        title: str,
        message: str,
        severity: NotificationSeverity = NotificationSeverity.INFO,
        channels: Optional[List[NotificationChannel]] = None,
        source: str = "system",
        source_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Send a notification through specified channels."""
        if channels is None:
            # Default channels based on severity
            if severity == NotificationSeverity.EMERGENCY:
                channels = [
                    NotificationChannel.SOUND,
                    NotificationChannel.VISUAL,
                    NotificationChannel.PUSH,
                    NotificationChannel.EMAIL,
                    NotificationChannel.SMS,
                    NotificationChannel.WEBSOCKET,
                ]
            elif severity == NotificationSeverity.CRITICAL:
                channels = [
                    NotificationChannel.SOUND,
                    NotificationChannel.VISUAL,
                    NotificationChannel.PUSH,
                    NotificationChannel.WEBSOCKET,
                ]
            elif severity == NotificationSeverity.WARNING:
                channels = [
                    NotificationChannel.VISUAL,
                    NotificationChannel.WEBSOCKET,
                ]
            else:
                channels = [NotificationChannel.VISUAL]

        notification = Notification(
            id=f"notif_{datetime.utcnow().timestamp()}",
            title=title,
            message=message,
            severity=severity,
            channels=channels,
            source=source,
            source_id=source_id,
            metadata=metadata or {},
        )

        # Store in history
        self._history.append(notification)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Dispatch to handlers
        for channel in channels:
            for handler in self._handlers.get(channel, []):
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(notification)
                    else:
                        handler(notification)
                except Exception as e:
                    logger.error(f"Notification handler failed for {channel}: {e}")

        logger.info(
            f"Notification sent: [{severity}] {title} "
            f"via {[c.value for c in channels]}"
        )

    async def send_alert(
        self,
        alert_type: str,
        alert_data: Dict[str, Any],
        severity: NotificationSeverity = NotificationSeverity.CRITICAL,
    ):
        """Send an alert notification (convenience method)."""
        title = f"🚨 {alert_type.upper()} Alert"
        message = alert_data.get("message", str(alert_data))
        await self.send(
            title=title,
            message=message,
            severity=severity,
            source="alert",
            source_id=alert_data.get("id"),
            metadata=alert_data,
        )

    async def send_soar_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
    ):
        """Send a SOAR event notification."""
        severity_map = {
            "playbook_started": NotificationSeverity.INFO,
            "playbook_completed": NotificationSeverity.INFO,
            "playbook_failed": NotificationSeverity.CRITICAL,
            "action_executed": NotificationSeverity.INFO,
            "action_failed": NotificationSeverity.WARNING,
            "incident_created": NotificationSeverity.CRITICAL,
            "incident_resolved": NotificationSeverity.INFO,
        }
        severity = severity_map.get(event_type, NotificationSeverity.INFO)

        await self.send(
            title=f"🔄 SOAR: {event_type}",
            message=event_data.get("message", str(event_data)),
            severity=severity,
            source="soar",
            source_id=event_data.get("execution_id"),
            metadata=event_data,
        )

    async def send_ml_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
    ):
        """Send an ML event notification."""
        severity_map = {
            "anomaly_detected": NotificationSeverity.CRITICAL,
            "drift_detected": NotificationSeverity.WARNING,
            "model_trained": NotificationSeverity.INFO,
            "model_deployed": NotificationSeverity.INFO,
            "model_failed": NotificationSeverity.CRITICAL,
        }
        severity = severity_map.get(event_type, NotificationSeverity.INFO)

        await self.send(
            title=f"🧠 ML: {event_type}",
            message=event_data.get("message", str(event_data)),
            severity=severity,
            source="ml",
            source_id=event_data.get("model_id"),
            metadata=event_data,
        )

    def get_history(
        self,
        limit: int = 50,
        severity: Optional[NotificationSeverity] = None,
        source: Optional[str] = None,
    ) -> List[Notification]:
        """Get notification history with filters."""
        result = self._history

        if severity:
            result = [n for n in result if n.severity == severity]
        if source:
            result = [n for n in result if n.source == source]

        return result[-limit:]

    def acknowledge(self, notification_id: str, user_id: str):
        """Acknowledge a notification."""
        for notification in self._history:
            if notification.id == notification_id:
                notification.read = True
                notification.acknowledged_by = user_id
                notification.acknowledged_at = datetime.utcnow()
                return True
        return False

    def enable_sound(self, enabled: bool = True):
        """Enable/disable sound notifications."""
        self._sound_enabled = enabled

    def enable_push(self, enabled: bool = True):
        """Enable/disable push notifications."""
        self._push_enabled = enabled


# Global notification manager instance
notification_manager = NotificationManager()


# WebSocket notification handler
async def websocket_notification_handler(notification: Notification):
    """Send notification via WebSocket."""
    from app.core.websocket_manager import ws_manager
    await ws_manager.broadcast({
        "type": "notification",
        "data": notification.dict(),
    })


# Register default handlers
notification_manager.register_handler(
    NotificationChannel.WEBSOCKET,
    websocket_notification_handler,
)


# Convenience functions
async def notify_critical(title: str, message: str, **kwargs):
    """Send a critical notification with sound."""
    await notification_manager.send(
        title=title,
        message=message,
        severity=NotificationSeverity.CRITICAL,
        **kwargs,
    )


async def notify_emergency(title: str, message: str, **kwargs):
    """Send an emergency notification (all channels)."""
    await notification_manager.send(
        title=title,
        message=message,
        severity=NotificationSeverity.EMERGENCY,
        **kwargs,
    )


async def notify_info(title: str, message: str, **kwargs):
    """Send an info notification."""
    await notification_manager.send(
        title=title,
        message=message,
        severity=NotificationSeverity.INFO,
        **kwargs,
    )
