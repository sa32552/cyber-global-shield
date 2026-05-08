"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Graceful Shutdown                    ║
║  Arrêt gracieux avec drain des workers et cleanup           ║
║  Évite la perte de données lors des redéploiements          ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    from app.core.shutdown import shutdown_handler
    
    # Register cleanup hooks
    shutdown_handler.register_cleanup("redis", lambda: redis_client.close())
    shutdown_handler.register_cleanup("kafka", lambda: kafka_producer.flush())
    
    # In FastAPI lifespan
    @asynccontextmanager
    async def lifespan(app):
        yield
        await shutdown_handler.shutdown()
"""

import os
import signal
import time
import asyncio
import structlog
from typing import Dict, Any, Optional, Callable, List, Awaitable
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

logger = structlog.get_logger(__name__)


@dataclass
class CleanupHook:
    """A cleanup hook to execute during shutdown."""
    name: str
    func: Callable[[], Awaitable[None]]
    timeout: float = 10.0
    critical: bool = False


class GracefulShutdown:
    """
    Gestionnaire d'arrêt gracieux.
    
    Séquence de shutdown:
    1. Stop accepting new requests
    2. Drain in-flight tasks (max 30s)
    3. Execute cleanup hooks
    4. Flush metrics
    5. Close connections
    """

    def __init__(self):
        self._shutdown_event = asyncio.Event()
        self._shutdown_in_progress = False
        self._cleanup_hooks: List[CleanupHook] = []
        self._active_tasks: set = set()
        self._start_time = time.time()
        self._shutdown_timeout = float(os.getenv("SHUTDOWN_TIMEOUT", "30"))
        self._stats = {
            "shutdowns": 0,
            "tasks_drained": 0,
            "hooks_executed": 0,
            "hooks_failed": 0,
            "total_shutdown_time_ms": 0,
        }

    def register_cleanup(self, name: str, func: Callable[[], Awaitable[None]], 
                         timeout: float = 10.0, critical: bool = False):
        """
        Register a cleanup hook.
        
        Args:
            name: Hook name for logging
            func: Async cleanup function
            timeout: Max execution time in seconds
            critical: If True, failure is logged as error
        """
        self._cleanup_hooks.append(CleanupHook(
            name=name,
            func=func,
            timeout=timeout,
            critical=critical,
        ))
        logger.info("cleanup_hook_registered", name=name, critical=critical)

    def track_task(self, task: asyncio.Task):
        """Track an active task for draining."""
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def shutdown(self, sig: Optional[signal.Signals] = None):
        """
        Execute graceful shutdown sequence.
        
        Args:
            sig: Signal that triggered shutdown (optional)
        """
        if self._shutdown_in_progress:
            logger.warning("shutdown_already_in_progress")
            return

        self._shutdown_in_progress = True
        shutdown_start = time.time()
        sig_name = sig.name if sig else "manual"

        logger.info(
            "shutdown_started",
            signal=sig_name,
            uptime_seconds=time.time() - self._start_time,
        )

        # 1. Signal shutdown
        self._shutdown_event.set()
        logger.info("shutdown_signaled", event="stop_accepting_requests")

        # 2. Drain in-flight tasks
        if self._active_tasks:
            logger.info(
                "draining_tasks",
                task_count=len(self._active_tasks),
                timeout=self._shutdown_timeout,
            )
            _, pending = await asyncio.wait(
                self._active_tasks,
                timeout=self._shutdown_timeout,
            )
            for task in pending:
                task.cancel()
                logger.debug("task_cancelled", task_name=task.get_name())
            self._stats["tasks_drained"] = len(self._active_tasks) - len(pending)
            logger.info(
                "tasks_drained",
                completed=len(self._active_tasks) - len(pending),
                cancelled=len(pending),
            )

        # 3. Execute cleanup hooks
        logger.info(
            "executing_cleanup_hooks",
            hook_count=len(self._cleanup_hooks),
        )
        for hook in self._cleanup_hooks:
            try:
                await asyncio.wait_for(hook.func(), timeout=hook.timeout)
                self._stats["hooks_executed"] += 1
                logger.debug("cleanup_hook_completed", name=hook.name)
            except asyncio.TimeoutError:
                self._stats["hooks_failed"] += 1
                msg = f"Cleanup hook '{hook.name}' timed out after {hook.timeout}s"
                if hook.critical:
                    logger.error(msg)
                else:
                    logger.warning(msg)
            except Exception as e:
                self._stats["hooks_failed"] += 1
                msg = f"Cleanup hook '{hook.name}' failed: {e}"
                if hook.critical:
                    logger.error(msg)
                else:
                    logger.warning(msg)

        # 4. Flush metrics
        try:
            await self._flush_metrics()
        except Exception as e:
            logger.warning("metrics_flush_failed", error=str(e))

        # 5. Final log
        shutdown_time = (time.time() - shutdown_start) * 1000
        self._stats["shutdowns"] += 1
        self._stats["total_shutdown_time_ms"] += shutdown_time

        logger.info(
            "shutdown_complete",
            signal=sig_name,
            shutdown_time_ms=round(shutdown_time, 2),
            hooks_executed=self._stats["hooks_executed"],
            tasks_drained=self._stats["tasks_drained"],
        )

    async def _flush_metrics(self):
        """Flush pending metrics."""
        try:
            from app.core.metrics import metrics
            prometheus_format = metrics.to_prometheus_format()
            if prometheus_format:
                logger.debug("metrics_flushed", size=len(prometheus_format))
        except ImportError:
            pass
        except Exception as e:
            logger.warning("metrics_flush_error", error=str(e))

    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutdown_in_progress or self._shutdown_event.is_set()

    def wait_for_shutdown(self) -> asyncio.Event:
        """Get shutdown event for waiting."""
        return self._shutdown_event

    def get_stats(self) -> Dict[str, Any]:
        """Get shutdown handler statistics."""
        return {
            "total_shutdowns": self._stats["shutdowns"],
            "total_tasks_drained": self._stats["tasks_drained"],
            "hooks_executed": self._stats["hooks_executed"],
            "hooks_failed": self._stats["hooks_failed"],
            "avg_shutdown_time_ms": round(
                self._stats["total_shutdown_time_ms"] / max(self._stats["shutdowns"], 1), 2
            ),
            "registered_hooks": len(self._cleanup_hooks),
            "active_tasks": len(self._active_tasks),
            "shutdown_timeout": self._shutdown_timeout,
            "shutdown_in_progress": self._shutdown_in_progress,
        }


# =============================================================================
# FastAPI Lifespan Helper
# =============================================================================

@asynccontextmanager
async def lifespan_handler(app):
    """
    FastAPI lifespan handler with graceful shutdown.
    
    Usage:
        app = FastAPI(lifespan=lifespan_handler)
    """
    # Startup
    logger.info("application_starting")
    yield
    # Shutdown
    logger.info("application_stopping")
    await shutdown_handler.shutdown()


# =============================================================================
# Signal Handler
# =============================================================================

def setup_signal_handlers():
    """Setup OS signal handlers for graceful shutdown."""
    loop = asyncio.get_event_loop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(shutdown_handler.shutdown(s)),
            )
            logger.info("signal_handler_registered", signal=sig.name)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            logger.warning("signal_handler_not_supported", signal=sig.name, platform="windows")


# Global shutdown handler
shutdown_handler = GracefulShutdown()
