"""
Cyber Global Shield — Self-Healing Infrastructure
Auto-réparation des systèmes compromis sans intervention humaine.
Restauration automatique, rollback, reconfiguration, et résilience.
"""

import json
import time
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class HealingAction(str, Enum):
    RESTART_SERVICE = "restart_service"
    ROLLBACK_DEPLOYMENT = "rollback_deployment"
    RECONFIGURE_FIREWALL = "reconfigure_firewall"
    RESTORE_BACKUP = "restore_backup"
    SCALE_UP = "scale_up"
    FAILOVER = "failover"
    CLEAN_CACHE = "clean_cache"
    RESET_CONNECTIONS = "reset_connections"
    UPDATE_DNS = "update_dns"
    RECREATE_CONTAINER = "recreate_container"


@dataclass
class HealingEvent:
    """A self-healing event."""
    timestamp: datetime
    action: HealingAction
    target: str
    reason: str
    status: str  # initiated, in_progress, completed, failed
    duration_ms: float = 0.0
    result: str = ""


class SelfHealingInfrastructure:
    """
    Infrastructure auto-réparatrice.
    
    Capacités:
    - Auto-restart des services défaillants
    - Rollback automatique des déploiements
    - Reconfiguration dynamique du firewall
    - Failover automatique
    - Restauration de backup
    - Scale-up automatique
    - Nettoyage de cache
    - Réinitialisation de connexions
    """

    def __init__(self):
        self._healing_history: List[HealingEvent] = []
        self._health_checks: Dict[str, Callable] = {}
        self._recovery_plans: Dict[str, List[Dict]] = self._load_recovery_plans()
        self._circuit_breakers: Dict[str, bool] = {}
        self._auto_mode = True

    def _load_recovery_plans(self) -> Dict[str, List[Dict]]:
        """Load recovery plans for different failure scenarios."""
        return {
            "service_crash": [
                {"action": HealingAction.RESTART_SERVICE, "timeout": 30, "retry": 3},
                {"action": HealingAction.RECREATE_CONTAINER, "timeout": 60, "retry": 2},
                {"action": HealingAction.FAILOVER, "timeout": 120, "retry": 1},
            ],
            "resource_exhaustion": [
                {"action": HealingAction.CLEAN_CACHE, "timeout": 10, "retry": 1},
                {"action": HealingAction.SCALE_UP, "timeout": 60, "retry": 2},
                {"action": HealingAction.RESET_CONNECTIONS, "timeout": 30, "retry": 1},
            ],
            "security_breach": [
                {"action": HealingAction.RECONFIGURE_FIREWALL, "timeout": 15, "retry": 1},
                {"action": HealingAction.RESET_CONNECTIONS, "timeout": 30, "retry": 1},
                {"action": HealingAction.RESTORE_BACKUP, "timeout": 300, "retry": 1},
            ],
            "deployment_failure": [
                {"action": HealingAction.ROLLBACK_DEPLOYMENT, "timeout": 60, "retry": 2},
                {"action": HealingAction.RESTART_SERVICE, "timeout": 30, "retry": 2},
            ],
            "network_partition": [
                {"action": HealingAction.UPDATE_DNS, "timeout": 30, "retry": 2},
                {"action": HealingAction.FAILOVER, "timeout": 120, "retry": 1},
                {"action": HealingAction.RECONFIGURE_FIREWALL, "timeout": 15, "retry": 1},
            ],
        }

    def register_health_check(self, name: str, check_fn: Callable):
        """Register a health check function."""
        self._health_checks[name] = check_fn
        logger.info(f"❤️ Health check registered: {name}")

    def heal(self, failure_type: str, target: str, reason: str) -> List[HealingEvent]:
        """Execute healing plan for a failure."""
        events = []
        plan = self._recovery_plans.get(failure_type)

        if not plan:
            logger.error(f"No recovery plan for: {failure_type}")
            return events

        # Check circuit breaker
        circuit_key = f"{failure_type}:{target}"
        if self._circuit_breakers.get(circuit_key):
            logger.warning(f"⛔ Circuit breaker open for {circuit_key}")
            return events

        logger.critical(f"🔧 Self-healing initiated: {failure_type} on {target}")

        for step in plan:
            event = self._execute_healing_step(step, target, reason)
            events.append(event)

            if event.status == "failed":
                logger.error(f"❌ Healing step failed: {step['action']}")
                if step.get("retry", 0) > 0:
                    # Retry logic
                    for attempt in range(step["retry"]):
                        logger.info(f"🔄 Retry {attempt + 1}/{step['retry']}")
                        event = self._execute_healing_step(step, target, reason)
                        events.append(event)
                        if event.status == "completed":
                            break
                else:
                    # Open circuit breaker
                    self._circuit_breakers[circuit_key] = True
                    logger.critical(f"⛔ Circuit breaker opened for {circuit_key}")
                    break

        return events

    def _execute_healing_step(
        self, step: Dict, target: str, reason: str
    ) -> HealingEvent:
        """Execute a single healing step."""
        action = step["action"]
        timeout = step.get("timeout", 30)

        event = HealingEvent(
            timestamp=datetime.utcnow(),
            action=action,
            target=target,
            reason=reason,
            status="initiated",
        )

        try:
            start = time.time()

            if action == HealingAction.RESTART_SERVICE:
                self._restart_service(target)
            elif action == HealingAction.ROLLBACK_DEPLOYMENT:
                self._rollback_deployment(target)
            elif action == HealingAction.RECONFIGURE_FIREWALL:
                self._reconfigure_firewall(target)
            elif action == HealingAction.RESTORE_BACKUP:
                self._restore_backup(target)
            elif action == HealingAction.SCALE_UP:
                self._scale_up(target)
            elif action == HealingAction.FAILOVER:
                self._failover(target)
            elif action == HealingAction.CLEAN_CACHE:
                self._clean_cache(target)
            elif action == HealingAction.RESET_CONNECTIONS:
                self._reset_connections(target)
            elif action == HealingAction.UPDATE_DNS:
                self._update_dns(target)
            elif action == HealingAction.RECREATE_CONTAINER:
                self._recreate_container(target)

            event.duration_ms = (time.time() - start) * 1000
            event.status = "completed"
            event.result = f"Successfully executed {action.value} on {target}"
            logger.info(f"✅ Healing: {action.value} on {target} completed in {event.duration_ms:.0f}ms")

        except Exception as e:
            event.status = "failed"
            event.result = str(e)
            logger.error(f"❌ Healing: {action.value} on {target} failed: {e}")

        self._healing_history.append(event)
        return event

    def _restart_service(self, target: str):
        """Simulate service restart."""
        logger.info(f"🔄 Restarting service: {target}")
        time.sleep(0.1)  # Simulated

    def _rollback_deployment(self, target: str):
        """Simulate deployment rollback."""
        logger.info(f"⏪ Rolling back deployment: {target}")
        time.sleep(0.1)

    def _reconfigure_firewall(self, target: str):
        """Simulate firewall reconfiguration."""
        logger.info(f"🔥 Reconfiguring firewall for: {target}")
        time.sleep(0.1)

    def _restore_backup(self, target: str):
        """Simulate backup restoration."""
        logger.info(f"💾 Restoring backup: {target}")
        time.sleep(0.1)

    def _scale_up(self, target: str):
        """Simulate scaling up."""
        logger.info(f"📈 Scaling up: {target}")
        time.sleep(0.1)

    def _failover(self, target: str):
        """Simulate failover."""
        logger.info(f"🔄 Failing over: {target}")
        time.sleep(0.1)

    def _clean_cache(self, target: str):
        """Simulate cache cleaning."""
        logger.info(f"🧹 Cleaning cache: {target}")
        time.sleep(0.1)

    def _reset_connections(self, target: str):
        """Simulate connection reset."""
        logger.info(f"🔌 Resetting connections: {target}")
        time.sleep(0.1)

    def _update_dns(self, target: str):
        """Simulate DNS update."""
        logger.info(f"🌐 Updating DNS: {target}")
        time.sleep(0.1)

    def _recreate_container(self, target: str):
        """Simulate container recreation."""
        logger.info(f"📦 Recreating container: {target}")
        time.sleep(0.1)

    def get_stats(self) -> Dict[str, Any]:
        """Get self-healing statistics."""
        total = len(self._healing_history)
        completed = len([e for e in self._healing_history if e.status == "completed"])
        failed = len([e for e in self._healing_history if e.status == "failed"])
        avg_duration = (
            sum(e.duration_ms for e in self._healing_history) / total
            if total > 0 else 0
        )

        return {
            "total_healing_events": total,
            "completed": completed,
            "failed": failed,
            "success_rate": (completed / total * 100) if total > 0 else 100.0,
            "avg_duration_ms": avg_duration,
            "circuit_breakers_open": sum(1 for v in self._circuit_breakers.values() if v),
            "health_checks": len(self._health_checks),
            "recovery_plans": len(self._recovery_plans),
            "mode": "AUTO" if self._auto_mode else "MANUAL",
            "status": "HEALING" if failed < total else "STABLE",
        }


self_healing = SelfHealingInfrastructure()
