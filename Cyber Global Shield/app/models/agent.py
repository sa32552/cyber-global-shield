import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Text, Float, Integer, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    agent_name: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    )  # triage_agent, investigation_agent, response_agent, threat_intel_agent
    task_type: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # triage, investigate, respond, enrich, correlate
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    parent_task_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    status: Mapped[str] = mapped_column(
        String(30), default="pending", index=True
    )  # pending, running, completed, failed, cancelled
    priority: Mapped[int] = mapped_column(Integer, default=5)  # 1-10, 10 highest
    input_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    output_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    reasoning_chain: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text))
    llm_model_used: Mapped[Optional[str]] = mapped_column(String(100))
    llm_tokens_used: Mapped[Optional[int]] = mapped_column(Integer)
    llm_cost: Mapped[Optional[float]] = mapped_column(Float)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class AgentDecision(Base):
    __tablename__ = "agent_decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_tasks.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    agent_name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    decision_type: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # escalate, block_ip, isolate_host, quarantine_file, alert, ignore, investigate
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reasoning: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    action_taken: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    action_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    action_success: Mapped[Optional[bool]] = mapped_column(Boolean)
    human_override: Mapped[bool] = mapped_column(Boolean, default=False)
    human_override_reason: Mapped[Optional[str]] = mapped_column(Text)
    override_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class SOARPlaybook(Base):
    __tablename__ = "soar_playbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    trigger_event: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    )  # high_alert, critical_alert, ransomware_detected, data_exfil, lateral_movement
    trigger_conditions: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    playbook_yaml: Mapped[str] = mapped_column(Text, nullable=False)  # Full YAML playbook
    actions: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)
    last_executed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    execution_count: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_execution_time_ms: Mapped[Optional[float]] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )