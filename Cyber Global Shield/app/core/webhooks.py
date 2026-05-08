"""
Cyber Global Shield — Webhook System
Webhooks with HMAC signature, retry with backoff, delivery tracking, and dashboard.
"""

import os
import json
import hmac
import hashlib
import time
import asyncio
import aiohttp
from typing import Optional, Dict, Any, List, Callable, Awaitable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

class WebhookEvent(str, Enum):
    """Types of webhook events."""
    ALERT_CREATED = "alert.created"
    ALERT_CRITICAL = "alert.critical"
    ALERT_RESOLVED = "alert.resolved"
    SOAR_STARTED = "soar.started"
    SOAR_COMPLETED = "soar.completed"
    SOAR_FAILED = "soar.failed"
    ML_ANOMALY = "ml.anomaly"
    ML_DRIFT = "ml.drift"
    ML_MODEL_DEPLOYED = "ml.model_deployed"
    SYSTEM_HEALTH = "system.health"
    SYSTEM_ERROR = "system.error"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"


@dataclass
class WebhookEndpoint:
    """Represents a registered webhook endpoint."""
    id: str
    url: str
    secret: str
    events: List[WebhookEvent]
    description: str = ""
    is_active: bool = True
    retry_count: int = 3
    timeout_seconds: int = 10
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_success: Optional[str] = None
    last_failure: Optional[str] = None
    total_deliveries: int = 0
    successful_deliveries: int = 0
    failed_deliveries: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_deliveries == 0:
            return 1.0
        return self.successful_deliveries / self.total_deliveries


@dataclass
class WebhookDelivery:
    """Represents a single webhook delivery attempt."""
    id: str
    endpoint_id: str
    event: WebhookEvent
    payload: Dict[str, Any]
    status: str  # pending, success, failed
    attempt: int = 1
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# =============================================================================
# Webhook Manager
# =============================================================================

class WebhookManager:
    """
    Manages webhook endpoints, delivery, retry logic, and tracking.
    """

    def __init__(self):
        self._endpoints: Dict[str, WebhookEndpoint] = {}
        self._deliveries: List[WebhookDelivery] = []
        self._max_delivery_history = 10000
        self._session: Optional[aiohttp.ClientSession] = None
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "CyberGlobalShield-Webhook/1.0"},
            )
        return self._session

    # =========================================================================
    # Endpoint Management
    # =========================================================================

    def register_endpoint(
        self,
        url: str,
        events: List[WebhookEvent],
        description: str = "",
        secret: Optional[str] = None,
        retry_count: int = 3,
        timeout_seconds: int = 10,
    ) -> WebhookEndpoint:
        """Register a new webhook endpoint."""
        import uuid
        endpoint_id = f"wh_{uuid.uuid4().hex[:12]}"
        webhook_secret = secret or os.urandom(32).hex()

        endpoint = WebhookEndpoint(
            id=endpoint_id,
            url=url,
            secret=webhook_secret,
            events=events,
            description=description,
            retry_count=retry_count,
            timeout_seconds=timeout_seconds,
        )

        self._endpoints[endpoint_id] = endpoint
        logger.info(
            "webhook_registered",
            endpoint_id=endpoint_id,
            url=url,
            events=[e.value for e in events],
        )

        return endpoint

    def update_endpoint(self, endpoint_id: str, **kwargs) -> Optional[WebhookEndpoint]:
        """Update a webhook endpoint."""
        endpoint = self._endpoints.get(endpoint_id)
        if not endpoint:
            return None

        for key, value in kwargs.items():
            if hasattr(endpoint, key):
                setattr(endpoint, key, value)

        logger.info("webhook_updated", endpoint_id=endpoint_id, updates=kwargs)
        return endpoint

    def delete_endpoint(self, endpoint_id: str) -> bool:
        """Delete a webhook endpoint."""
        if endpoint_id in self._endpoints:
            del self._endpoints[endpoint_id]
            logger.info("webhook_deleted", endpoint_id=endpoint_id)
            return True
        return False

    def get_endpoint(self, endpoint_id: str) -> Optional[WebhookEndpoint]:
        """Get a webhook endpoint by ID."""
        return self._endpoints.get(endpoint_id)

    def list_endpoints(self, event: Optional[WebhookEvent] = None) -> List[WebhookEndpoint]:
        """List all endpoints, optionally filtered by event type."""
        if event:
            return [e for e in self._endpoints.values() if event in e.events and e.is_active]
        return list(self._endpoints.values())

    # =========================================================================
    # Webhook Delivery
    # =========================================================================

    async def dispatch(
        self,
        event: WebhookEvent,
        payload: Dict[str, Any],
        source: str = "system",
    ) -> List[WebhookDelivery]:
        """
        Dispatch an event to all subscribed webhook endpoints.
        Returns list of delivery results.
        """
        endpoints = self.list_endpoints(event)
        if not endpoints:
            return []

        deliveries = []
        tasks = []

        for endpoint in endpoints:
            delivery = WebhookDelivery(
                id=f"del_{hashlib.md5(f'{endpoint.id}_{time.time()}'.encode()).hexdigest()[:12]}",
                endpoint_id=endpoint.id,
                event=event,
                payload=payload,
                status="pending",
            )
            self._deliveries.append(delivery)
            deliveries.append(delivery)
            tasks.append(self._deliver_with_retry(endpoint, delivery))

        # Execute all deliveries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Trim delivery history
        if len(self._deliveries) > self._max_delivery_history:
            self._deliveries = self._deliveries[-self._max_delivery_history:]

        # Log summary
        success_count = sum(1 for d in deliveries if d.status == "success")
        logger.info(
            "webhook_dispatched",
            event=event.value,
            endpoints=len(endpoints),
            successful=success_count,
            failed=len(deliveries) - success_count,
        )

        return deliveries

    async def _deliver_with_retry(self, endpoint: WebhookEndpoint, delivery: WebhookDelivery):
        """Deliver webhook with retry logic (exponential backoff)."""
        for attempt in range(1, endpoint.retry_count + 1):
            delivery.attempt = attempt
            start_time = time.time()

            try:
                success = await self._send_webhook(endpoint, delivery)
                delivery.duration_ms = (time.time() - start_time) * 1000

                if success:
                    delivery.status = "success"
                    endpoint.last_success = datetime.now(timezone.utc).isoformat()
                    endpoint.successful_deliveries += 1
                    endpoint.total_deliveries += 1
                    return

                delivery.status = "failed"
                endpoint.last_failure = datetime.now(timezone.utc).isoformat()
                endpoint.failed_deliveries += 1
                endpoint.total_deliveries += 1

            except Exception as e:
                delivery.status = "failed"
                delivery.error_message = str(e)
                delivery.duration_ms = (time.time() - start_time) * 1000
                endpoint.last_failure = datetime.now(timezone.utc).isoformat()
                endpoint.failed_deliveries += 1
                endpoint.total_deliveries += 1

                logger.warning(
                    "webhook_delivery_failed",
                    endpoint_id=endpoint.id,
                    attempt=attempt,
                    error=str(e),
                )

            # Exponential backoff before retry
            if attempt < endpoint.retry_count:
                backoff = 2 ** attempt  # 2s, 4s, 8s
                await asyncio.sleep(backoff)

    async def _send_webhook(self, endpoint: WebhookEndpoint, delivery: WebhookDelivery) -> bool:
        """Send a single webhook request with HMAC signature."""
        session = await self._get_session()

        # Prepare payload
        body = json.dumps({
            "event": delivery.event.value,
            "id": delivery.id,
            "timestamp": delivery.timestamp,
            "data": delivery.payload,
        })

        # Generate HMAC signature
        signature = hmac.new(
            endpoint.secret.encode(),
            body.encode(),
            hashlib.sha256,
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": f"sha256={signature}",
            "X-Webhook-Event": delivery.event.value,
            "X-Webhook-ID": delivery.id,
            "X-Webhook-Timestamp": delivery.timestamp,
        }

        try:
            async with session.post(
                endpoint.url,
                data=body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=endpoint.timeout_seconds),
            ) as response:
                delivery.status_code = response.status
                delivery.response_body = await response.text()[:1000]  # Truncate

                # 2xx = success
                return 200 <= response.status < 300

        except asyncio.TimeoutError:
            delivery.error_message = "Request timed out"
            return False
        except aiohttp.ClientError as e:
            delivery.error_message = f"HTTP client error: {str(e)}"
            return False

    # =========================================================================
    # Event Handlers (for internal routing)
    # =========================================================================

    def on(self, event: WebhookEvent, handler: Callable[[Dict[str, Any]], Awaitable[None]]):
        """Register an event handler."""
        event_key = event.value
        if event_key not in self._event_handlers:
            self._event_handlers[event_key] = []
        self._event_handlers[event_key].append(handler)

    async def emit(self, event: WebhookEvent, data: Dict[str, Any], source: str = "system"):
        """
        Emit an event to both webhook endpoints and internal handlers.
        This is the main entry point for all events.
        """
        # Dispatch to webhook endpoints
        await self.dispatch(event, data, source=source)

        # Dispatch to internal handlers
        event_key = event.value
        if event_key in self._event_handlers:
            for handler in self._event_handlers[event_key]:
                try:
                    await handler(data)
                except Exception as e:
                    logger.error("webhook_handler_failed", event=event_key, error=str(e))

    # =========================================================================
    # Analytics & Monitoring
    # =========================================================================

    def get_delivery_history(
        self,
        endpoint_id: Optional[str] = None,
        event: Optional[WebhookEvent] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[WebhookDelivery]:
        """Get delivery history with optional filters."""
        deliveries = self._deliveries

        if endpoint_id:
            deliveries = [d for d in deliveries if d.endpoint_id == endpoint_id]
        if event:
            deliveries = [d for d in deliveries if d.event == event]
        if status:
            deliveries = [d for d in deliveries if d.status == status]

        return deliveries[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get webhook system statistics."""
        total_deliveries = len(self._deliveries)
        successful = sum(1 for d in self._deliveries if d.status == "success")
        failed = sum(1 for d in self._deliveries if d.status == "failed")

        return {
            "total_endpoints": len(self._endpoints),
            "active_endpoints": sum(1 for e in self._endpoints.values() if e.is_active),
            "total_deliveries": total_deliveries,
            "successful_deliveries": successful,
            "failed_deliveries": failed,
            "success_rate": successful / max(total_deliveries, 1),
            "endpoints": [
                {
                    "id": e.id,
                    "url": e.url,
                    "events": [ev.value for ev in e.events],
                    "is_active": e.is_active,
                    "success_rate": e.success_rate,
                    "total_deliveries": e.total_deliveries,
                    "last_success": e.last_success,
                    "last_failure": e.last_failure,
                }
                for e in self._endpoints.values()
            ],
        }

    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()


# =============================================================================
# Convenience Functions
# =============================================================================

# Global webhook manager instance
webhook_manager = WebhookManager()


async def emit_alert(alert_type: str, alert_data: Dict[str, Any]):
    """Emit an alert event to webhooks."""
    event_map = {
        "critical": WebhookEvent.ALERT_CRITICAL,
        "created": WebhookEvent.ALERT_CREATED,
        "resolved": WebhookEvent.ALERT_RESOLVED,
    }
    event = event_map.get(alert_type, WebhookEvent.ALERT_CREATED)
    await webhook_manager.emit(event, alert_data, source="alert_system")


async def emit_soar_event(status: str, playbook_data: Dict[str, Any]):
    """Emit a SOAR event to webhooks."""
    event_map = {
        "started": WebhookEvent.SOAR_STARTED,
        "completed": WebhookEvent.SOAR_COMPLETED,
        "failed": WebhookEvent.SOAR_FAILED,
    }
    event = event_map.get(status, WebhookEvent.SOAR_STARTED)
    await webhook_manager.emit(event, playbook_data, source="soar_engine")


async def emit_ml_event(event_type: str, ml_data: Dict[str, Any]):
    """Emit an ML event to webhooks."""
    event_map = {
        "anomaly": WebhookEvent.ML_ANOMALY,
        "drift": WebhookEvent.ML_DRIFT,
        "model_deployed": WebhookEvent.ML_MODEL_DEPLOYED,
    }
    event = event_map.get(event_type, WebhookEvent.ML_ANOMALY)
    await webhook_manager.emit(event, ml_data, source="ml_system")


async def emit_system_event(event_type: str, system_data: Dict[str, Any]):
    """Emit a system event to webhooks."""
    event_map = {
        "health": WebhookEvent.SYSTEM_HEALTH,
        "error": WebhookEvent.SYSTEM_ERROR,
    }
    event = event_map.get(event_type, WebhookEvent.SYSTEM_HEALTH)
    await webhook_manager.emit(event, system_data, source="system_monitor")
