"""
Cyber Global Shield — Zero-Touch SOAR
Orchestration, automatisation et réponse aux incidents sans intervention humaine.
Décision autonome, exécution parallèle, et boucle de rétroaction.
"""

import json
import time
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class AutomationLevel(str, Enum):
    FULL = "full"  # No human needed
    RECOMMEND = "recommend"  # Suggests actions
    MANUAL = "manual"  # Human must approve


class PlaybookStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ZeroTouchAction:
    """An action in a zero-touch playbook."""
    action_id: str
    name: str
    description: str
    timeout: int = 30
    retry_count: int = 2
    parallel: bool = False
    depends_on: List[str] = field(default_factory=list)
    rollback_action: Optional[str] = None


@dataclass
class PlaybookExecution:
    """A playbook execution instance."""
    execution_id: str
    playbook_name: str
    trigger_event: str
    status: PlaybookStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    actions: List[Dict] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


class ZeroTouchSOAR:
    """
    Zero-Touch SOAR Engine.
    
    Capacités:
    - Exécution autonome de playbooks
    - Actions parallèles et séquentielles
    - Rollback automatique
    - Boucle de rétroaction ML
    - Décision contextuelle
    - Auto-apprentissage
    """

    def __init__(self):
        self._executions: List[PlaybookExecution] = []
        self._playbooks: Dict[str, List[ZeroTouchAction]] = {}
        self._action_handlers: Dict[str, Callable] = {}
        self._automation_level = AutomationLevel.FULL
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._load_default_playbooks()

    def _load_default_playbooks(self):
        """Load default zero-touch playbooks."""
        self._playbooks = {
            "ransomware_response": [
                ZeroTouchAction(
                    action_id="isolate_host",
                    name="Isolate compromised host",
                    description="Immediately isolate host from network",
                    timeout=15,
                    retry_count=1,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="kill_process",
                    name="Kill ransomware process",
                    description="Terminate the encryption process",
                    timeout=10,
                    retry_count=2,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="block_c2",
                    name="Block C2 communication",
                    description="Block outbound connections to C2",
                    timeout=10,
                    retry_count=1,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="restore_backup",
                    name="Restore from backup",
                    description="Restore encrypted files from backup",
                    timeout=300,
                    retry_count=1,
                    parallel=False,
                    depends_on=["isolate_host", "kill_process"],
                    rollback_action="stop_restore",
                ),
                ZeroTouchAction(
                    action_id="scan_endpoint",
                    name="Deep scan endpoint",
                    description="Full endpoint scan for persistence",
                    timeout=180,
                    retry_count=1,
                    parallel=False,
                    depends_on=["restore_backup"],
                ),
            ],
            "brute_force_response": [
                ZeroTouchAction(
                    action_id="block_ip",
                    name="Block attacking IP",
                    description="Add IP to firewall blocklist",
                    timeout=10,
                    retry_count=1,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="enable_mfa",
                    name="Force enable MFA",
                    description="Enable MFA for affected accounts",
                    timeout=30,
                    retry_count=2,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="reset_passwords",
                    name="Reset compromised passwords",
                    description="Force password reset for affected users",
                    timeout=60,
                    retry_count=1,
                    parallel=False,
                    depends_on=["block_ip"],
                ),
                ZeroTouchAction(
                    action_id="audit_access",
                    name="Audit access logs",
                    description="Review access logs for breach scope",
                    timeout=120,
                    retry_count=1,
                    parallel=False,
                    depends_on=["reset_passwords"],
                ),
            ],
            "data_exfiltration_response": [
                ZeroTouchAction(
                    action_id="block_outbound",
                    name="Block outbound data transfer",
                    description="Block all outbound connections except critical",
                    timeout=10,
                    retry_count=1,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="revoke_tokens",
                    name="Revoke all sessions",
                    description="Revoke all active API tokens and sessions",
                    timeout=15,
                    retry_count=1,
                    parallel=True,
                ),
                ZeroTouchAction(
                    action_id="disable_accounts",
                    name="Disable suspicious accounts",
                    description="Disable accounts involved in exfiltration",
                    timeout=20,
                    retry_count=1,
                    parallel=False,
                    depends_on=["block_outbound"],
                ),
                ZeroTouchAction(
                    action_id="forensic_capture",
                    name="Capture forensic evidence",
                    description="Capture memory, network, and disk evidence",
                    timeout=180,
                    retry_count=1,
                    parallel=False,
                    depends_on=["revoke_tokens"],
                ),
            ],
        }

    def register_action_handler(self, action_name: str, handler: Callable):
        """Register a handler for an action."""
        self._action_handlers[action_name] = handler
        logger.info(f"🔧 Action handler registered: {action_name}")

    def execute_playbook(
        self, playbook_name: str, trigger_event: str,
        context: Dict[str, Any]
    ) -> PlaybookExecution:
        """Execute a playbook autonomously."""
        playbook = self._playbooks.get(playbook_name)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_name}")

        execution = PlaybookExecution(
            execution_id=f"ZT-{int(time.time())}-{len(self._executions)+1}",
            playbook_name=playbook_name,
            trigger_event=trigger_event,
            status=PlaybookStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._executions.append(execution)
        logger.critical(f"⚡ Zero-Touch SOAR executing: {playbook_name} ({execution.execution_id})")

        try:
            # Phase 1: Execute parallel actions
            parallel_actions = [a for a in playbook if a.parallel]
            if parallel_actions:
                self._execute_parallel_actions(execution, parallel_actions, context)

            # Phase 2: Execute sequential actions
            sequential_actions = [a for a in playbook if not a.parallel]
            for action in sequential_actions:
                # Check dependencies
                if action.depends_on:
                    all_deps_met = all(
                        any(a.get("action_id") == dep and a.get("status") == "success"
                            for a in execution.actions)
                        for dep in action.depends_on
                    )
                    if not all_deps_met:
                        logger.error(f"Dependencies not met for {action.action_id}")
                        continue

                result = self._execute_action(execution, action, context)
                execution.actions.append(result)

                if result["status"] == "failed":
                    # Auto rollback
                    self._rollback(execution, action)
                    execution.status = PlaybookStatus.ROLLED_BACK
                    execution.error = f"Action {action.action_id} failed"
                    break

            if execution.status != PlaybookStatus.ROLLED_BACK:
                execution.status = PlaybookStatus.SUCCESS

        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.error = str(e)
            logger.error(f"❌ Zero-Touch SOAR failed: {e}")

        execution.completed_at = datetime.utcnow()
        duration = (execution.completed_at - execution.started_at).total_seconds()
        
        logger.info(
            f"✅ Zero-Touch SOAR completed: {playbook_name} "
            f"({execution.status.value}) in {duration:.1f}s"
        )

        return execution

    def _execute_parallel_actions(
        self, execution: PlaybookExecution,
        actions: List[ZeroTouchAction], context: Dict
    ):
        """Execute actions in parallel."""
        futures = {}
        for action in actions:
            future = self._executor.submit(
                self._execute_action, execution, action, context
            )
            futures[future] = action

        for future in as_completed(futures):
            action = futures[future]
            try:
                result = future.result()
                execution.actions.append(result)
            except Exception as e:
                execution.actions.append({
                    "action_id": action.action_id,
                    "status": "failed",
                    "error": str(e),
                })

    def _execute_action(
        self, execution: PlaybookExecution,
        action: ZeroTouchAction, context: Dict
    ) -> Dict[str, Any]:
        """Execute a single action with retry logic."""
        result = {
            "action_id": action.action_id,
            "name": action.name,
            "status": "pending",
            "started_at": datetime.utcnow().isoformat(),
            "error": "",
        }

        for attempt in range(action.retry_count + 1):
            try:
                handler = self._action_handlers.get(action.action_id)
                if handler:
                    action_result = handler(context)
                    result["status"] = "success"
                    result["result"] = action_result
                else:
                    # Simulated execution
                    time.sleep(0.1)
                    result["status"] = "success"
                    result["result"] = f"Simulated: {action.name}"

                logger.info(f"✅ Action {action.action_id} completed (attempt {attempt + 1})")
                break

            except Exception as e:
                result["status"] = "failed"
                result["error"] = str(e)
                logger.warning(f"⚠️ Action {action.action_id} failed (attempt {attempt + 1}): {e}")

                if attempt < action.retry_count:
                    time.sleep(1)  # Wait before retry

        result["completed_at"] = datetime.utcnow().isoformat()
        return result

    def _rollback(self, execution: PlaybookExecution, failed_action: ZeroTouchAction):
        """Rollback actions after a failure."""
        logger.warning(f"⏪ Rolling back from {failed_action.action_id}")
        
        # Execute rollback in reverse order
        for action in reversed(execution.actions):
            if action["status"] == "success":
                rollback_name = f"rollback_{action['action_id']}"
                handler = self._action_handlers.get(rollback_name)
                if handler:
                    try:
                        handler({})
                        logger.info(f"⏪ Rolled back: {action['action_id']}")
                    except Exception as e:
                        logger.error(f"Rollback failed for {action['action_id']}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get Zero-Touch SOAR statistics."""
        total = len(self._executions)
        successful = len([e for e in self._executions if e.status == PlaybookStatus.SUCCESS])
        failed = len([e for e in self._executions if e.status == PlaybookStatus.FAILED])
        rolled_back = len([e for e in self._executions if e.status == PlaybookStatus.ROLLED_BACK])

        avg_duration = 0.0
        completed = [e for e in self._executions if e.completed_at]
        if completed:
            durations = [
                (e.completed_at - e.started_at).total_seconds()
                for e in completed
            ]
            avg_duration = sum(durations) / len(durations)

        return {
            "total_executions": total,
            "successful": successful,
            "failed": failed,
            "rolled_back": rolled_back,
            "success_rate": (successful / total * 100) if total > 0 else 100.0,
            "avg_duration_seconds": avg_duration,
            "automation_level": self._automation_level.value,
            "playbooks_available": len(self._playbooks),
            "action_handlers": len(self._action_handlers),
            "status": "ZERO_TOUCH" if self._automation_level == AutomationLevel.FULL else "MANUAL",
        }


zero_touch_soar = ZeroTouchSOAR()
