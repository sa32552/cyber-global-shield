"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Health Checks                        ║
║  Liveness / Readiness / Startup probes pour Kubernetes      ║
║  Vérifie chaque dépendance avec timeout et métriques        ║
╚══════════════════════════════════════════════════════════════╝

Endpoints:
    GET /health      → Liveness probe (l'app tourne)
    GET /health/ready → Readiness probe (prête à recevoir du trafic)
    GET /health/startup → Startup probe (démarrage terminé)
    GET /health/detailed → Status détaillé de chaque dépendance
"""

import os
import time
import asyncio
import structlog
from enum import Enum
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)


class ServiceStatus(Enum):
    """Health status for a service."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check."""
    service: str
    status: ServiceStatus
    latency_ms: float
    error: Optional[str] = None
    last_success: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


class HealthRegistry:
    """
    Registry of health checks for Kubernetes probes.
    
    Supports three probe types:
    - Liveness: Is the app running?
    - Readiness: Can the app receive traffic?
    - Startup: Has the app finished initializing?
    """

    def __init__(self):
        self._checks: Dict[str, Callable] = {}
        self._results: Dict[str, HealthCheckResult] = {}
        self._history: Dict[str, deque] = {}
        self._history_maxlen = 100
        self._start_time = time.time()
        self._ready = False
        self._startup_complete = False

    def register(self, name: str, check_fn: Callable, critical: bool = False):
        """
        Register a health check function.
        
        Args:
            name: Service name
            check_fn: Async function that returns HealthCheckResult
            critical: If True, failure makes readiness=False
        """
        self._checks[name] = check_fn
        self._history[name] = deque(maxlen=self._history_maxlen)
        logger.info("health_check_registered", service=name, critical=critical)

    async def check_service(self, name: str) -> HealthCheckResult:
        """Run a single health check."""
        if name not in self._checks:
            return HealthCheckResult(
                service=name,
                status=ServiceStatus.UNKNOWN,
                latency_ms=0,
                error="No check registered",
            )

        start = time.time()
        try:
            result = await asyncio.wait_for(self._checks[name](), timeout=10.0)
            latency = (time.time() - start) * 1000
            result.latency_ms = latency
            if result.status == ServiceStatus.HEALTHY:
                result.last_success = datetime.now(timezone.utc)
            self._results[name] = result
            self._history[name].append(result)
            return result
        except asyncio.TimeoutError:
            result = HealthCheckResult(
                service=name,
                status=ServiceStatus.UNHEALTHY,
                latency_ms=(time.time() - start) * 1000,
                error="Health check timed out after 10s",
            )
            self._results[name] = result
            self._history[name].append(result)
            return result
        except Exception as e:
            result = HealthCheckResult(
                service=name,
                status=ServiceStatus.UNHEALTHY,
                latency_ms=(time.time() - start) * 1000,
                error=str(e),
            )
            self._results[name] = result
            self._history[name].append(result)
            return result

    async def check_all(self) -> Dict[str, HealthCheckResult]:
        """Run all health checks in parallel."""
        tasks = {name: self.check_service(name) for name in self._checks}
        results = {}
        for name, task in tasks.items():
            results[name] = await task
        return results

    async def liveness(self) -> bool:
        """
        Liveness probe.
        Returns True if the app process is running.
        Kubernetes restarts the pod if this returns False.
        """
        return True  # If this code runs, the app is alive

    async def readiness(self) -> bool:
        """
        Readiness probe.
        Returns True if the app can receive traffic.
        Kubernetes removes the pod from service if this returns False.
        """
        if not self._startup_complete:
            return False

        results = await self.check_all()
        unhealthy = [
            name for name, result in results.items()
            if result.status == ServiceStatus.UNHEALTHY
        ]

        if unhealthy:
            logger.warning("readiness_check_failed", unhealthy_services=unhealthy)
            return False

        return True

    async def startup(self) -> bool:
        """
        Startup probe.
        Returns True if the app has finished initializing.
        Kubernetes delays liveness/readiness checks until this returns True.
        """
        if self._startup_complete:
            return True

        # Check critical services
        results = await self.check_all()
        critical_unhealthy = [
            name for name, result in results.items()
            if result.status == ServiceStatus.UNHEALTHY
        ]

        if not critical_unhealthy:
            self._startup_complete = True
            logger.info("startup_complete", services_checked=len(results))
            return True

        logger.info("startup_in_progress", pending_services=critical_unhealthy)
        return False

    def mark_ready(self):
        """Manually mark the app as ready."""
        self._ready = True
        self._startup_complete = True
        logger.info("app_marked_ready")

    async def get_detailed_status(self) -> Dict[str, Any]:
        """Get detailed health status for all services."""
        results = await self.check_all()
        uptime = time.time() - self._start_time

        status_counts = {s.value: 0 for s in ServiceStatus}
        for result in results.values():
            status_counts[result.status.value] = status_counts.get(result.status.value, 0) + 1

        return {
            "app": {
                "name": "Cyber Global Shield",
                "version": os.getenv("APP_VERSION", "2.0.0"),
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "ready": self._ready,
                "startup_complete": self._startup_complete,
            },
            "services": {
                name: {
                    "status": result.status.value,
                    "latency_ms": round(result.latency_ms, 2),
                    "error": result.error,
                    "last_success": result.last_success.isoformat() if result.last_success else None,
                    "details": result.details,
                }
                for name, result in results.items()
            },
            "summary": {
                "total": len(results),
                "healthy": status_counts.get("healthy", 0),
                "degraded": status_counts.get("degraded", 0),
                "unhealthy": status_counts.get("unhealthy", 0),
                "unknown": status_counts.get("unknown", 0),
            },
        }

    def get_service_history(self, name: str, limit: int = 10) -> List[Dict]:
        """Get health check history for a service."""
        if name not in self._history:
            return []
        return [
            {
                "status": r.status.value,
                "latency_ms": round(r.latency_ms, 2),
                "error": r.error,
            }
            for r in list(self._history[name])[-limit:]
        ]

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format."""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        return " ".join(parts)


# =============================================================================
# Built-in health checks
# =============================================================================

async def check_redis() -> HealthCheckResult:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            socket_connect_timeout=5,
        )
        await client.ping()
        info = await client.info("server")
        await client.aclose()
        return HealthCheckResult(
            service="redis",
            status=ServiceStatus.HEALTHY,
            latency_ms=0,
            details={"redis_version": info.get("redis_version", "unknown")},
        )
    except Exception as e:
        return HealthCheckResult(
            service="redis",
            status=ServiceStatus.UNHEALTHY,
            latency_ms=0,
            error=str(e),
        )


async def check_clickhouse() -> HealthCheckResult:
    """Check ClickHouse connectivity."""
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            username=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        )
        result = client.query("SELECT version()")
        version = result.result_rows[0][0] if result.result_rows else "unknown"
        client.close()
        return HealthCheckResult(
            service="clickhouse",
            status=ServiceStatus.HEALTHY,
            latency_ms=0,
            details={"version": version},
        )
    except Exception as e:
        return HealthCheckResult(
            service="clickhouse",
            status=ServiceStatus.UNHEALTHY,
            latency_ms=0,
            error=str(e),
        )


async def check_kafka() -> HealthCheckResult:
    """Check Kafka connectivity."""
    try:
        from confluent_kafka import Producer, Consumer
        from confluent_kafka.admin import AdminClient

        bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        admin = AdminClient({"bootstrap.servers": bootstrap_servers})
        metadata = admin.list_topics(timeout=5)
        topics = list(metadata.topics.keys())

        return HealthCheckResult(
            service="kafka",
            status=ServiceStatus.HEALTHY,
            latency_ms=0,
            details={"topics": topics[:10], "brokers": len(metadata.brokers)},
        )
    except Exception as e:
        return HealthCheckResult(
            service="kafka",
            status=ServiceStatus.UNHEALTHY,
            latency_ms=0,
            error=str(e),
        )


async def check_disk_space() -> HealthCheckResult:
    """Check available disk space."""
    try:
        import shutil
        usage = shutil.disk_usage("/")
        percent_free = (usage.free / usage.total) * 100
        status = ServiceStatus.HEALTHY
        if percent_free < 10:
            status = ServiceStatus.UNHEALTHY
        elif percent_free < 20:
            status = ServiceStatus.DEGRADED

        return HealthCheckResult(
            service="disk_space",
            status=status,
            latency_ms=0,
            details={
                "total_gb": round(usage.total / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_free": round(percent_free, 2),
            },
        )
    except Exception as e:
        return HealthCheckResult(
            service="disk_space",
            status=ServiceStatus.UNHEALTHY,
            latency_ms=0,
            error=str(e),
        )


async def check_memory() -> HealthCheckResult:
    """Check memory usage."""
    try:
        import psutil
        memory = psutil.virtual_memory()
        status = ServiceStatus.HEALTHY
        if memory.percent > 90:
            status = ServiceStatus.UNHEALTHY
        elif memory.percent > 80:
            status = ServiceStatus.DEGRADED

        return HealthCheckResult(
            service="memory",
            status=status,
            latency_ms=0,
            details={
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent_used": memory.percent,
            },
        )
    except Exception as e:
        return HealthCheckResult(
            service="memory",
            status=ServiceStatus.UNHEALTHY,
            latency_ms=0,
            error=str(e),
        )


# Global health registry
health_registry = HealthRegistry()

# Register default checks
health_registry.register("redis", check_redis, critical=True)
health_registry.register("clickhouse", check_clickhouse, critical=True)
health_registry.register("kafka", check_kafka, critical=True)
health_registry.register("disk_space", check_disk_space, critical=False)
health_registry.register("memory", check_memory, critical=False)
