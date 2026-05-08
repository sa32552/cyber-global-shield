"""
Tests unitaires pour le module SOAR (playbook_engine + integrations).
Teste : DAG execution, locking, audit trail, rollback, TheHive, MISP.
"""

import asyncio
import pytest
from datetime import datetime, timezone
from app.soar.playbook_engine import (
    SOAREngine, SOARPlaybook, ActionStatus, ActionResult, PlaybookResult,
    AuditTrail, ExecutionLock, DAGExecutor, get_soar,
)
from app.soar.integrations import (
    TheHiveClient, MISPClient, IntegrationManager, get_integrations,
)


# ─── Tests AuditTrail ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_trail_record_and_retrieve():
    audit = AuditTrail(max_entries=100)
    await audit.record("playbook_started", "test_pb", "exec_1", {"key": "val"})
    await audit.record("action_completed", "test_pb", "exec_1", {"action": "block_ip"})
    await audit.record("playbook_completed", "test_pb", "exec_1", {"status": "completed"})

    history = await audit.get_history(limit=10)
    assert len(history) == 3
    assert history[0]["action"] == "playbook_started"
    assert history[1]["action"] == "action_completed"
    assert history[2]["action"] == "playbook_completed"


@pytest.mark.asyncio
async def test_audit_trail_filter_by_playbook():
    audit = AuditTrail(max_entries=100)
    await audit.record("started", "pb1", "e1", {})
    await audit.record("started", "pb2", "e2", {})

    pb1_history = await audit.get_history(playbook_name="pb1")
    assert len(pb1_history) == 1
    assert pb1_history[0]["playbook"] == "pb1"


@pytest.mark.asyncio
async def test_audit_trail_execution_log():
    audit = AuditTrail(max_entries=100)
    await audit.record("started", "pb", "exec_42", {"ctx": "test"})
    await audit.record("completed", "pb", "exec_42", {"status": "ok"})

    log = await audit.get_execution_log("exec_42")
    assert len(log) == 2
    assert log[0]["action"] == "started"
    assert log[1]["action"] == "completed"


# ─── Tests ExecutionLock ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execution_lock_acquire_release():
    lock = ExecutionLock()
    acquired = await lock.acquire("ransomware", "exec_1")
    assert acquired is True
    assert await lock.is_locked("ransomware") is True

    await lock.release("ransomware", "exec_1")
    assert await lock.is_locked("ransomware") is False


@pytest.mark.asyncio
async def test_execution_lock_contention():
    lock = ExecutionLock()
    await lock.acquire("resource_a", "exec_1")
    acquired = await lock.acquire("resource_a", "exec_2")
    assert acquired is False  # Should be blocked


@pytest.mark.asyncio
async def test_execution_lock_get_locks():
    lock = ExecutionLock()
    await lock.acquire("res1", "e1")
    await lock.acquire("res2", "e2")
    locks = await lock.get_locks()
    assert locks == {"res1": "e1", "res2": "e2"}


# ─── Tests DAGExecutor ─────────────────────────────────────────────────

def test_dag_build():
    dag = DAGExecutor()
    actions = [
        {"name": "a", "depends_on": []},
        {"name": "b", "depends_on": ["a"]},
        {"name": "c", "depends_on": ["a"]},
        {"name": "d", "depends_on": ["b", "c"]},
    ]
    result = dag.build_dag(actions)
    assert result == {"a": set(), "b": {"a"}, "c": {"a"}, "d": {"b", "c"}}


def test_dag_topological_sort():
    dag = DAGExecutor()
    actions = [
        {"name": "a", "depends_on": []},
        {"name": "b", "depends_on": ["a"]},
        {"name": "c", "depends_on": ["a"]},
        {"name": "d", "depends_on": ["b", "c"]},
    ]
    d = dag.build_dag(actions)
    levels = dag.topological_sort(d)
    assert len(levels) == 3
    assert levels[0] == ["a"]  # Level 0: a
    assert set(levels[1]) == {"b", "c"}  # Level 1: b, c (parallel)
    assert levels[2] == ["d"]  # Level 2: d


def test_dag_cycle_detection():
    dag = DAGExecutor()
    actions = [
        {"name": "a", "depends_on": ["b"]},
        {"name": "b", "depends_on": ["a"]},
    ]
    d = dag.build_dag(actions)
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.topological_sort(d)


def test_dag_template_resolution():
    dag = DAGExecutor()
    action = {"name": "test", "params": {"host": "{{ patient_zero }}", "ips": "{{ iocs.ips }}"}}
    context = {"patient_zero": "10.0.0.5", "iocs": {"ips": ["1.2.3.4"]}}
    resolved = dag._resolve_template(action, context)
    assert resolved["params"]["host"] == "10.0.0.5"
    assert resolved["params"]["ips"] == ["1.2.3.4"]


# ─── Tests SOAREngine ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_soar_engine_playbooks_loaded():
    engine = get_soar()
    playbooks = await engine.get_available_playbooks()
    assert len(playbooks) >= 5
    names = [pb["name"] for pb in playbooks]
    assert "ransomware_response" in names
    assert "lateral_movement_response" in names
    assert "data_exfiltration_response" in names
    assert "c2_communication_response" in names
    assert "brute_force_response" in names


@pytest.mark.asyncio
async def test_soar_engine_dry_run():
    engine = get_soar()
    result = await engine.execute_playbook(
        "ransomware_response",
        {"patient_zero": "10.0.0.50", "iocs": {"ips": ["5.5.5.5"], "domains": ["evil.com"]}},
        dry_run=True,
    )
    assert result.status == ActionStatus.SKIPPED
    assert len(result.actions_results) == 8  # 8 actions in ransomware playbook


@pytest.mark.asyncio
async def test_soar_engine_execution():
    engine = get_soar()
    result = await engine.execute_playbook(
        "ransomware_response",
        {
            "patient_zero": "10.0.0.50",
            "iocs": {"ips": ["5.5.5.5"], "domains": ["evil.com"]},
            "compromised_users": ["admin@corp.com"],
        },
    )
    assert result.status in (ActionStatus.COMPLETED, ActionStatus.ROLLED_BACK)
    assert len(result.actions_results) > 0
    assert result.execution_id != ""


@pytest.mark.asyncio
async def test_soar_engine_cooldown():
    engine = get_soar()
    # First execution
    await engine.execute_playbook(
        "ransomware_response",
        {"patient_zero": "10.0.0.50", "iocs": {"ips": [], "domains": []}},
    )
    # Second execution should be skipped due to cooldown
    result = await engine.execute_playbook(
        "ransomware_response",
        {"patient_zero": "10.0.0.50", "iocs": {"ips": [], "domains": []}},
    )
    assert result.status == ActionStatus.SKIPPED


@pytest.mark.asyncio
async def test_soar_engine_lock_contention():
    engine = get_soar()
    # Acquire lock manually
    await engine.locks.acquire("brute_force_response", "external_exec")
    result = await engine.execute_playbook(
        "brute_force_response",
        {"alert": {"src_ip": "1.2.3.4", "user": "test@corp.com"}},
    )
    assert result.status == ActionStatus.BLOCKED
    await engine.locks.release("brute_force_response", "external_exec")


@pytest.mark.asyncio
async def test_soar_engine_audit_trail():
    engine = get_soar()
    result = await engine.execute_playbook(
        "brute_force_response",
        {"alert": {"src_ip": "1.2.3.4", "user": "test@corp.com"}},
    )
    log = await engine.get_execution_log(result.execution_id)
    assert len(log) >= 2  # At least started + completed


@pytest.mark.asyncio
async def test_soar_engine_health_check():
    engine = get_soar()
    health = await engine.health_check()
    assert health["status"] == "healthy"
    assert health["playbooks_loaded"] >= 5
    assert health["action_handlers"] >= 10


# ─── Tests TheHiveClient ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_thehive_create_alert_simulated():
    client = TheHiveClient(base_url="", api_key="")
    result = await client.create_alert(
        title="Test Alert",
        description="Test description",
        severity=2,
        tags=["test"],
    )
    assert result["status"] == "simulated"
    assert "SIM-" in result["alert_id"]


@pytest.mark.asyncio
async def test_thehive_create_case_simulated():
    client = TheHiveClient(base_url="", api_key="")
    result = await client.create_case(
        title="Test Case",
        description="Test case description",
        severity=3,
    )
    assert result["status"] == "simulated"


@pytest.mark.asyncio
async def test_thehive_add_observable_simulated():
    client = TheHiveClient(base_url="", api_key="")
    result = await client.add_observable(
        case_id="case_123",
        data_type="ip",
        data="1.2.3.4",
        tags=["ioc"],
    )
    assert result["status"] == "simulated"


# ─── Tests MISPClient ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_misp_create_event_simulated():
    client = MISPClient(base_url="", api_key="")
    result = await client.create_event(
        info="Test MISP Event",
        threat_level=2,
        tags=["test"],
    )
    assert result["status"] == "simulated"
    assert "SIM-" in result["event_id"]


@pytest.mark.asyncio
async def test_misp_add_attribute_simulated():
    client = MISPClient(base_url="", api_key="")
    result = await client.add_attribute(
        event_id="event_123",
        attribute_type="ip-src",
        value="5.5.5.5",
        category="Network activity",
    )
    assert result["status"] == "simulated"


@pytest.mark.asyncio
async def test_misp_publish_event_simulated():
    client = MISPClient(base_url="", api_key="")
    result = await client.publish_event(event_id="event_123")
    assert result["status"] == "simulated"


@pytest.mark.asyncio
async def test_misp_search_attributes_no_url():
    client = MISPClient(base_url="", api_key="")
    result = await client.search_attributes(value="1.2.3.4")
    assert result == []


# ─── Tests IntegrationManager ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_integration_manager_singletons():
    mgr = get_integrations()
    assert mgr.firewall is not None
    assert mgr.edr is not None
    assert mgr.iam is not None
    assert mgr.dns is not None
    assert mgr.notifications is not None
    assert mgr.tickets is not None
    assert mgr.thehive is not None
    assert mgr.misp is not None


@pytest.mark.asyncio
async def test_integration_manager_health_check():
    mgr = get_integrations()
    health = await mgr.health_check()
    assert "firewall" in health
    assert "edr" in health
    assert "iam" in health
    assert "dns" in health
    assert "notifications" in health
    assert "tickets" in health
    assert "thehive" in health
    assert "misp" in health


# ─── Tests de bout en bout ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_soar_pipeline():
    """Test complet : playbook → audit → locks → health."""
    engine = get_soar()

    # 1. Execute playbook
    result = await engine.execute_playbook(
        "c2_communication_response",
        {
            "alert": {"src_ip": "10.0.0.100"},
            "iocs": {"c2_ips": ["5.5.5.5", "6.6.6.6"], "c2_domains": ["c2.evil.com"]},
        },
    )
    assert result.status in (ActionStatus.COMPLETED, ActionStatus.ROLLED_BACK)

    # 2. Check audit trail
    log = await engine.get_execution_log(result.execution_id)
    assert len(log) >= 2

    # 3. Check no active locks
    locks = await engine.get_active_locks()
    assert result.playbook_name not in locks

    # 4. Health check
    health = await engine.health_check()
    assert health["status"] == "healthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
