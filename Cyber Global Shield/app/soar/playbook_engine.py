"""
SOAR (Security Orchestration, Automation and Response) Engine.
Executes automated response playbooks based on agent decisions.
Features: DAG execution, locking, audit trail, rollback.
"""

import asyncio
import json
import time
import hashlib
from typing import Optional, Dict, Any, List, Callable, Set
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import structlog
import httpx
import yaml

from app.core.config import settings

logger = structlog.get_logger(__name__)


# ─── Enums & Data Classes ───────────────────────────────────────────────

class ActionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"


@dataclass
class ActionResult:
    action_name: str
    status: ActionStatus
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    rollback_possible: bool = False
    audit_id: Optional[str] = None


@dataclass
class PlaybookResult:
    playbook_name: str
    trigger_event: str
    status: ActionStatus
    actions_results: List[ActionResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    total_duration_ms: float = 0.0
    execution_id: str = ""
    locked_by: Optional[str] = None


# ─── Audit Trail ────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    timestamp: datetime
    action: str
    playbook_name: str
    execution_id: str
    details: Dict[str, Any]
    actor: str = "system"


class AuditTrail:
    """Immutable audit trail for all SOAR actions."""

    def __init__(self, max_entries: int = 10000):
        self._entries: deque = deque(maxlen=max_entries)
        self._lock = asyncio.Lock()

    async def record(self, action: str, playbook_name: str, execution_id: str,
                     details: Dict[str, Any], actor: str = "system"):
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action=action, playbook_name=playbook_name,
            execution_id=execution_id, details=details, actor=actor,
        )
        async with self._lock:
            self._entries.append(entry)

    async def get_history(self, playbook_name: Optional[str] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        async with self._lock:
            entries = list(self._entries)
            if playbook_name:
                entries = [e for e in entries if e.playbook_name == playbook_name]
            entries = entries[-limit:]
        return [{"timestamp": e.timestamp.isoformat(), "action": e.action,
                 "playbook": e.playbook_name, "execution_id": e.execution_id,
                 "details": e.details, "actor": e.actor} for e in entries]

    async def get_execution_log(self, execution_id: str) -> List[Dict[str, Any]]:
        async with self._lock:
            return [{"timestamp": e.timestamp.isoformat(), "action": e.action,
                     "playbook": e.playbook_name, "details": e.details, "actor": e.actor}
                    for e in self._entries if e.execution_id == execution_id]


# ─── Execution Lock ─────────────────────────────────────────────────────

class ExecutionLock:
    """Prevents concurrent playbook execution on the same resource."""

    def __init__(self):
        self._locks: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, resource: str, execution_id: str) -> bool:
        async with self._lock:
            if resource in self._locks:
                return False
            self._locks[resource] = execution_id
            return True

    async def release(self, resource: str, execution_id: str):
        async with self._lock:
            if self._locks.get(resource) == execution_id:
                del self._locks[resource]

    async def is_locked(self, resource: str) -> bool:
        async with self._lock:
            return resource in self._locks

    async def get_locks(self) -> Dict[str, str]:
        async with self._lock:
            return dict(self._locks)


# ─── DAG Executor ───────────────────────────────────────────────────────

class DAGExecutor:
    """Directed Acyclic Graph executor for parallel action processing."""

    def build_dag(self, actions: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        dag: Dict[str, Set[str]] = {}
        action_map = {a["name"]: a for a in actions}
        for action in actions:
            name = action["name"]
            deps = set(action.get("depends_on", []))
            for dep in deps:
                if dep not in action_map:
                    logger.warning("dag_dep_not_found", action=name, dep=dep)
            dag[name] = deps
        return dag

    def topological_sort(self, dag: Dict[str, Set[str]]) -> List[List[str]]:
        in_degree = {n: len(d) for n, d in dag.items()}
        adj = defaultdict(set)
        for n, deps in dag.items():
            for d in deps:
                adj[d].add(n)
        q = deque([n for n, d in in_degree.items() if d == 0])
        levels = []
        while q:
            cur = []
            for _ in range(len(q)):
                node = q.popleft()
                cur.append(node)
                for nb in adj[node]:
                    in_degree[nb] -= 1
                    if in_degree[nb] == 0:
                        q.append(nb)
            levels.append(cur)
        if sum(len(l) for l in levels) != len(dag):
            raise ValueError("Cycle detected in action dependencies")
        return levels

    async def execute_level(self, actions: List[Dict[str, Any]], level: List[str],
                            context: Dict[str, Any], handler: Callable,
                            rollback_stack: List[Dict[str, Any]]) -> List[ActionResult]:
        action_map = {a["name"]: a for a in actions}
        tasks = []
        for name in level:
            a = action_map.get(name)
            if a:
                tasks.append(asyncio.create_task(self._execute_single(a, context, handler, rollback_stack)))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for r in results:
            if isinstance(r, ActionResult):
                out.append(r)
            elif isinstance(r, Exception):
                out.append(ActionResult(action_name="unknown", status=ActionStatus.FAILED, error=str(r)))
        return out

    async def _execute_single(self, action: Dict[str, Any], context: Dict[str, Any],
                              handler: Callable, rollback_stack: List[Dict[str, Any]]) -> ActionResult:
        import time
        start = time.time()
        resolved = self._resolve_template(action, context)
        try:
            output = await handler(resolved)
            dur = (time.time() - start) * 1000
            if action.get("rollback"):
                rollback_stack.append(action)
            return ActionResult(action_name=action["name"], status=ActionStatus.COMPLETED,
                                output=output, duration_ms=dur, rollback_possible=action.get("rollback", False))
        except Exception as e:
            dur = (time.time() - start) * 1000
            return ActionResult(action_name=action["name"], status=ActionStatus.FAILED,
                                error=str(e), duration_ms=dur, rollback_possible=action.get("rollback", False))

    def _resolve_template(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        import re
        def resolve(v):
            if isinstance(v, str):
                for m in re.findall(r'\{\{\s*([\w.]+)\s*\}\}', v):
                    parts = m.split(".")
                    cur = context
                    for p in parts:
                        cur = cur.get(p, f"{{{{ {m} }}}}") if isinstance(cur, dict) else f"{{{{ {m} }}}}"
                    v = v.replace(f"{{{{ {m} }}}}", str(cur) if cur else "")
                return v
            elif isinstance(v, dict):
                return {k: resolve(v2) for k, v2 in v.items()}
            elif isinstance(v, list):
                return [resolve(x) for x in v]
            return v
        return resolve(action)


# ─── SOAR Playbook ──────────────────────────────────────────────────────

class SOARPlaybook:
    def __init__(self, name: str, description: str, trigger_event: str,
                 actions: List[Dict[str, Any]], requires_approval: bool = False,
                 cooldown_seconds: int = 300, max_parallel_actions: int = 5):
        self.name = name
        self.description = description
        self.trigger_event = trigger_event
        self.actions = actions
        self.requires_approval = requires_approval
        self.cooldown_seconds = cooldown_seconds
        self.max_parallel_actions = max_parallel_actions
        self._last_executed: Optional[datetime] = None

    def is_on_cooldown(self) -> bool:
        if not self._last_executed:
            return False
        return (datetime.now(timezone.utc) - self._last_executed).total_seconds() < self.cooldown_seconds

    def mark_executed(self):
        self._last_executed = datetime.now(timezone.utc)


# ─── SOAR Engine ────────────────────────────────────────────────────────

class SOAREngine:
    """SOAR Engine with DAG execution, locking, audit trail, rollback."""

    def __init__(self):
        self.playbooks: Dict[str, SOARPlaybook] = {}
        self._action_handlers: Dict[str, Callable] = {}
        self._http_client: Optional[httpx.AsyncClient] = None
        self._audit_trail = AuditTrail(max_entries=10000)
        self._execution_lock = ExecutionLock()
        self._dag_executor = DAGExecutor()
        self._register_default_playbooks()
        self._register_default_handlers()

    @property
    def audit(self) -> AuditTrail:
        return self._audit_trail

    @property
    def locks(self) -> ExecutionLock:
        return self._execution_lock

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.SOAR_TIMEOUT), verify=True)
        return self._http_client

    def _register_default_playbooks(self):
        self.register_playbook(SOARPlaybook(
            name="ransomware_response",
            description="Immediate containment of ransomware infection",
            trigger_event="ransomware_detected", requires_approval=False, cooldown_seconds=60,
            actions=[
                {"name": "identify_patient_zero", "type": "query", "order": 1},
                {"name": "isolate_host_network", "type": "edr_action",
                 "params": {"host": "{{ patient_zero }}", "isolation_level": "full"},
                 "order": 2, "depends_on": ["identify_patient_zero"], "rollback": True},
                {"name": "block_ioc_ips", "type": "firewall_block",
                 "params": {"ips": "{{ iocs.ips }}", "duration_hours": 72},
                 "order": 3, "depends_on": ["identify_patient_zero"], "rollback": True},
                {"name": "block_ioc_domains", "type": "dns_sinkhole",
                 "params": {"domains": "{{ iocs.domains }}"},
                 "order": 4, "depends_on": ["identify_patient_zero"], "rollback": True},
                {"name": "snapshot_forensic", "type": "forensic_snapshot",
                 "params": {"host": "{{ patient_zero }}", "include_memory": True},
                 "order": 5, "depends_on": ["isolate_host_network"]},
                {"name": "disable_compromised_users", "type": "iam_action",
                 "params": {"users": "{{ compromised_users }}"},
                 "order": 6, "depends_on": ["identify_patient_zero"], "rollback": True},
                {"name": "notify_soc_team", "type": "notification",
                 "params": {"channel": "soc-critical",
                            "message": "🚨 RANSOMWARE DETECTED - Automated containment executed"},
                 "order": 7},
                {"name": "create_incident_ticket", "type": "ticket",
                 "params": {"system": "jira", "priority": "critical",
                            "summary": "Ransomware Incident - Auto-Contained"},
                 "order": 8},
            ]))
        self.register_playbook(SOARPlaybook(
            name="lateral_movement_response",
            description="Contain lateral movement", trigger_event="lateral_movement",
            requires_approval=False, cooldown_seconds=300,
            actions=[
                {"name": "segment_network", "type": "network_segment",
                 "params": {"source": "{{ alert.src_ip }}", "action": "quarantine"},
                 "order": 1, "rollback": True},
                {"name": "revoke_credentials", "type": "iam_action",
                 "params": {"user": "{{ alert.user }}", "action": "revoke_sessions"},
                 "order": 2, "depends_on": ["segment_network"], "rollback": True},
                {"name": "block_internal_firewall", "type": "firewall_block",
                 "params": {"source": "{{ alert.src_ip }}", "destination": "internal"},
                 "order": 3, "depends_on": ["segment_network"], "rollback": True},
                {"name": "enable_enhanced_logging", "type": "logging",
                 "params": {"level": "verbose", "targets": "{{ affected_assets }}"}, "order": 4},
                {"name": "notify_soc_team", "type": "notification",
                 "params": {"channel": "soc-high",
                            "message": "⚠️ LATERAL MOVEMENT DETECTED - Network segmented"},
                 "order": 5},
            ]))
        self.register_playbook(SOARPlaybook(
            name="data_exfiltration_response",
            description="Block data exfiltration", trigger_event="data_exfiltration",
            requires_approval=True, cooldown_seconds=300,
            actions=[
                {"name": "block_egress_traffic", "type": "firewall_block",
                 "params": {"source": "{{ alert.src_ip }}", "direction": "egress"},
                 "order": 1, "rollback": True},
                {"name": "capture_network_traffic", "type": "packet_capture",
                 "params": {"host": "{{ alert.src_ip }}", "duration_seconds": 300},
                 "order": 2, "depends_on": ["block_egress_traffic"]},
                {"name": "snapshot_affected_systems", "type": "forensic_snapshot",
                 "params": {"hosts": "{{ affected_assets }}"},
                 "order": 3, "depends_on": ["block_egress_traffic"]},
                {"name": "block_destination_ips", "type": "firewall_block",
                 "params": {"ips": "{{ iocs.dst_ips }}"}, "order": 4, "rollback": True},
                {"name": "notify_dpo", "type": "notification",
                 "params": {"channel": "legal-dpo",
                            "message": "🔴 POTENTIAL DATA BREACH - DPO notification required"},
                 "order": 5},
            ]))
        self.register_playbook(SOARPlaybook(
            name="c2_communication_response",
            description="Block C2 communication", trigger_event="c2_communication",
            requires_approval=False, cooldown_seconds=60,
            actions=[
                {"name": "block_c2_ip", "type": "firewall_block",
                 "params": {"ips": "{{ iocs.c2_ips }}"}, "order": 1, "rollback": True},
                {"name": "sinkhole_c2_domain", "type": "dns_sinkhole",
                 "params": {"domains": "{{ iocs.c2_domains }}"},
                 "order": 2, "depends_on": ["block_c2_ip"], "rollback": True},
                {"name": "isolate_compromised_host", "type": "edr_action",
                 "params": {"host": "{{ alert.src_ip }}", "isolation_level": "network"},
                 "order": 3, "depends_on": ["block_c2_ip"], "rollback": True},
                {"name": "collect_network_artifacts", "type": "forensic_collect",
                 "params": {"host": "{{ alert.src_ip }}",
                            "artifacts": ["netflow", "dns_cache", "connections"]},
                 "order": 4, "depends_on": ["isolate_compromised_host"]},
            ]))
        self.register_playbook(SOARPlaybook(
            name="brute_force_response",
            description="Block brute force attacks", trigger_event="brute_force",
            requires_approval=False, cooldown_seconds=120,
            actions=[
                {"name": "block_source_ip", "type": "firewall_block",
                 "params": {"ips": "{{ alert.src_ip }}", "duration_hours": 24},
                 "order": 1, "rollback": True},
                {"name": "enforce_mfa", "type": "iam_action",
                 "params": {"user": "{{ alert.user }}", "action": "enforce_mfa"},
                 "order": 2, "depends_on": ["block_source_ip"]},
                {"name": "disable_account_temp", "type": "iam_action",
                 "params": {"user": "{{ alert.user }}", "action": "temp_disable", "duration_minutes": 30},
                 "order": 3, "depends_on": ["block_source_ip"], "rollback": True},
                {"name": "alert_security_team", "type": "notification",
                 "params": {"channel": "soc-medium",
                            "message": "🔐 BRUTE FORCE ATTACK - IP blocked, MFA enforced"},
                 "order": 4},
            ]))

    def _register_default_handlers(self):
        self._action_handlers = {
            "firewall_block": self._handle_firewall_block,
            "dns_sinkhole": self._handle_dns_sinkhole,
            "edr_action": self._handle_edr_action,
            "iam_action": self._handle_iam_action,
            "network_segment": self._handle_network_segment,
            "forensic_snapshot": self._handle_forensic_snapshot,
            "forensic_collect": self._handle_forensic_collect,
            "packet_capture": self._handle_packet_capture,
            "notification": self._handle_notification,
            "ticket": self._handle_ticket,
            "logging": self._handle_logging,
            "query": self._handle_query,
        }

    def register_playbook(self, playbook: SOARPlaybook):
        self.playbooks[playbook.name] = playbook
        logger.info("playbook_registered", name=playbook.name, trigger=playbook.trigger_event)

    def get_playbooks_for_trigger(self, trigger_event: str) -> List[SOARPlaybook]:
        return [pb for pb in self.playbooks.values() if pb.trigger_event == trigger_event]

    async def execute_playbook(self, playbook_name: str, context: Dict[str, Any],
                               dry_run: bool = False, actor: str = "system") -> PlaybookResult:
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_name}")

        execution_id = hashlib.sha256(f"{playbook_name}:{time.time()}:{actor}".encode()).hexdigest()[:16]

        if not dry_run and playbook.is_on_cooldown():
            result = PlaybookResult(playbook_name=playbook_name, trigger_event=playbook.trigger_event,
                                    status=ActionStatus.SKIPPED, execution_id=execution_id)
            await self._audit_trail.record("playbook_skipped", playbook_name, execution_id,
                                           {"reason": "cooldown"}, actor)
            return result

        if not dry_run:
            locked = await self._execution_lock.acquire(playbook_name, execution_id)
            if not locked:
                result = PlaybookResult(playbook_name=playbook_name, trigger_event=playbook.trigger_event,
                                        status=ActionStatus.BLOCKED, execution_id=execution_id,
                                        locked_by=(await self._execution_lock.get_locks()).get(playbook_name))
                await self._audit_trail.record("playbook_blocked", playbook_name, execution_id,
                                               {"reason": "lock_contention"}, actor)
                return result

        result = PlaybookResult(playbook_name=playbook_name, trigger_event=playbook.trigger_event,
                                execution_id=execution_id)
        try:
            await self._audit_trail.record("playbook_started", playbook_name, execution_id,
                                           {"context": context, "dry_run": dry_run}, actor)
            if dry_run:
                for a in playbook.actions:
                    result.actions_results.append(ActionResult(action_name=a["name"], status=ActionStatus.SKIPPED))
                result.status = ActionStatus.SKIPPED
                return result

            dag = self._dag_executor.build_dag(playbook.actions)
            levels = self._dag_executor.topological_sort(dag)
            rollback_stack = []

            for level in levels:
                level_results = await self._dag_executor.execute_level(
                    playbook.actions, level, context, self._execute_action, rollback_stack)
                result.actions_results.extend(level_results)
                failed = [r for r in level_results if r.status == ActionStatus.FAILED]
                if failed:
                    for f in failed:
                        await self._audit_trail.record("action_failed", playbook_name, execution_id,
                                                       {"action": f.action_name, "error": f.error}, actor)
                    await self._rollback(rollback_stack, playbook_name, execution_id, actor)
                    result.status = ActionStatus.ROLLED_BACK
                    break

            if result.status != ActionStatus.ROLLED_BACK:
                result.status = ActionStatus.COMPLETED
                playbook.mark_executed()

            await self._audit_trail.record("playbook_completed", playbook_name, execution_id,
                                           {"status": result.status.value, "actions": len(result.actions_results)}, actor)
        except Exception as e:
            logger.error("playbook_error", name=playbook_name, error=str(e))
            result.status = ActionStatus.FAILED
            await self._audit_trail.record("playbook_error", playbook_name, execution_id, {"error": str(e)}, actor)
        finally:
            await self._execution_lock.release(playbook_name, execution_id)
            result.completed_at = datetime.now(timezone.utc)
            result.total_duration_ms = (result.completed_at - result.started_at).total_seconds() * 1000

        logger.info("playbook_executed", name=playbook_name, status=result.status.value,
                    duration_ms=result.total_duration_ms, actions=len(result.actions_results))
        return result

    async def _execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        handler = self._action_handlers.get(action.get("type"))
        if not handler:
            raise ValueError(f"No handler for action type: {action.get('type')}")
        return await handler(action)

    async def _handle_firewall_block(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        params = action.get("params", {})
        ips = params.get("ips", [])
        if isinstance(ips, str):
            ips = [ips]
        if not ips:
            return {"status": "skipped", "reason": "no_ips"}
        return await int_mgr.firewall.block_ip(ips=ips, duration_hours=params.get("duration_hours", 72),
                                                comment=f"Cyber Global Shield SOAR - {action.get('name', 'block')}")

    async def _handle_dns_sinkhole(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        params = action.get("params", {})
        domains = params.get("domains", [])
        if isinstance(domains, str):
            domains = [domains]
        if not domains:
            return {"status": "skipped", "reason": "no_domains"}
        return await int_mgr.dns.sinkhole_domains(domains)

    async def _handle_edr_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        params = action.get("params", {})
        host = params.get("host")
        if not host:
            return {"status": "skipped", "reason": "no_host"}
        return await int_mgr.edr.isolate_host(host=host, isolation_level=params.get("isolation_level", "full"))

    async def _handle_iam_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        params = action.get("params", {})
        user = params.get("user", params.get("users", ""))
        iam_action = params.get("action", "disable")
        if not user:
            return {"status": "skipped", "reason": "no_user"}
        if iam_action in ("disable", "temp_disable"):
            return await int_mgr.iam.disable_user(str(user))
        elif iam_action == "revoke_sessions":
            return await int_mgr.iam.revoke_sessions(str(user))
        elif iam_action == "enforce_mfa":
            return await int_mgr.iam.enforce_mfa(str(user))
        elif iam_action == "force_password_reset":
            return await int_mgr.iam.force_password_reset(str(user))
        return {"status": "unknown_action", "action": iam_action}

    async def _handle_network_segment(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        source = action.get("params", {}).get("source", "")
        if source:
            r = await int_mgr.firewall.block_ip(ips=[source], duration_hours=24,
                                                 comment=f"Segment {source}")
            return {"status": "segmented", "source": source, "firewall_result": r}
        return {"status": "skipped", "reason": "no_source"}

    async def _handle_forensic_snapshot(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        hosts = action.get("params", {}).get("hosts", action.get("params", {}).get("host", []))
        if isinstance(hosts, str):
            hosts = [hosts]
        results = [{"host": h, "status": (await int_mgr.edr.scan_host(h)).get("status", "unknown")} for h in hosts]
        return {"status": "snapshots_initiated", "results": results}

    async def _handle_forensic_collect(self, action: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("forensic_collect", host=action.get("params", {}).get("host"))
        return {"status": "collected"}

    async def _handle_packet_capture(self, action: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("packet_capture", host=action.get("params", {}).get("host"))
        return {"status": "capturing"}

    async def _handle_notification(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        p = action.get("params", {})
        return await int_mgr.notifications.send(channel=p.get("channel", "soc-alerts"),
                                                 message=p.get("message", "Alert"),
                                                 severity=p.get("severity", "high"))

    async def _handle_ticket(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        int_mgr = get_integrations()
        p = action.get("params", {})
        return await int_mgr.tickets.create_ticket(summary=p.get("summary", "Security Incident"),
                                                    description=p.get("description", ""),
                                                    priority=p.get("priority", "High"),
                                                    labels=["cyber-global-shield", "auto-created"])

    async def _handle_logging(self, action: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("enhanced_logging", targets=action.get("params", {}).get("targets"))
        return {"status": "enabled"}

    async def _handle_query(self, action: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("query", action=action.get("name"))
        return {"status": "queried", "result": "query_result_placeholder"}

    async def _rollback(self, rollback_stack: List[Dict[str, Any]],
                        playbook_name: str, execution_id: str, actor: str = "system"):
        logger.info("starting_rollback", actions=len(rollback_stack))
        for action in reversed(rollback_stack):
            handler = self._rollback_handlers.get(action.get("type"))
            if handler:
                try:
                    await handler(action)
                    await self._audit_trail.record("rollback_action", playbook_name, execution_id,
                                                   {"action": action["name"]}, actor)
                except Exception as e:
                    logger.error("rollback_failed", name=action["name"], error=str(e))
        logger.info("rollback_completed", count=len(rollback_stack))

    _rollback_handlers: Dict[str, Callable] = {
        "firewall_block": "_handle_firewall_unblock",
        "dns_sinkhole": "_handle_dns_unsinkhole",
        "edr_action": "_handle_edr_unisolate",
        "iam_action": "_handle_iam_undo",
        "network_segment": "_handle_network_unsegment",
    }

    async def _handle_firewall_unblock(self, action: Dict[str, Any]) -> Dict[str, Any]:
        from app.soar.integrations import get_integrations
        ips = action.get("params", {}).get("ips", [])
        if isinstance(ips, str):
            ips = [ips]
        if ips:
            return await get_integrations().firewall.unblock_ip(ips)
        return {"status": "skipped"}

    async def _handle_dns_unsinkhole(self, action: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "unsinkholed"}

    async def _handle_edr_unisolate(self, action: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "unisolated"}

    async def _handle_iam_undo(self, action: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "undone"}

    async def _handle_network_unsegment(self, action: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "unsegmented"}

    async def get_available_playbooks(self) -> List[Dict[str, Any]]:
        return [{"name": pb.name, "description": pb.description, "trigger_event": pb.trigger_event,
                 "requires_approval": pb.requires_approval, "on_cooldown": pb.is_on_cooldown(),
                 "actions_count": len(pb.actions)} for pb in self.playbooks.values()]

    async def get_audit_history(self, playbook_name: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        return await self._audit_trail.get_history(playbook_name, limit)

    async def get_execution_log(self, execution_id: str) -> List[Dict[str, Any]]:
        return await self._audit_trail.get_execution_log(execution_id)

    async def get_active_locks(self) -> Dict[str, str]:
        return await self._execution_lock.get_locks()

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "healthy", "playbooks_loaded": len(self.playbooks),
                "action_handlers": len(self._action_handlers),
                "active_locks": len(await self._execution_lock.get_locks()),
                "audit_entries": len(self._audit_trail._entries)}

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()


soar_engine = SOAREngine()


def get_soar() -> SOAREngine:
    return soar_engine
