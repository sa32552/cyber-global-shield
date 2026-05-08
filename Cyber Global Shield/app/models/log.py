import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Text, Float, Integer, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(100), index=True, nullable=False)  # zeek, osquery, pyshark, suricata
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info")  # info, low, medium, high, critical
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    normalized_payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(20))
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255))
    process_id: Mapped[Optional[int]] = mapped_column(Integer)
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    hash_md5: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    hash_sha256: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    processing_latency_ms: Mapped[Optional[float]] = mapped_column(Float)

    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="log", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("logs.id", ondelete="CASCADE"), index=True
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    alert_type: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    )  # anomaly, signature, ml_detected, zero_day, threat_intel
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(
        String(20), default="medium"
    )  # info, low, medium, high, critical
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0.0 - 1.0
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0.0 - 100.0
    status: Mapped[str] = mapped_column(
        String(30), default="open", index=True
    )  # open, investigating, resolved, false_positive, escalated
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100))  # TA0001, TA0002...
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100))  # T1190, T1059...
    kill_chain_phase: Mapped[Optional[str]] = mapped_column(String(50))
    affected_assets: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    iocs: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)  # IPs, domains, hashes, URLs
    investigation_notes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    resolution: Mapped[Optional[str]] = mapped_column(Text)
    auto_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_by_agent: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    log: Mapped["Log"] = relationship("Log", back_populates="alerts")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source: Mapped[str] = mapped_column(
        String(100), index=True, nullable=False
    )  # misp, cortex, virustotal, alienvault, custom
    indicator_type: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # ip, domain, url, hash, email
    indicator_value: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    campaign: Mapped[Optional[str]] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    raw_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    tlp: Mapped[str] = mapped_column(String(10), default="green")  # white, green, amber, red
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class RawPacket(Base):
    __tablename__ = "raw_packets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packet_size: Mapped[int] = mapped_column(Integer)
    payload_hex: Mapped[Optional[str]] = mapped_column(Text)
    payload_ascii: Mapped[Optional[str]] = mapped_column(Text)
    flags: Mapped[Optional[str]] = mapped_column(String(50))  # TCP flags
    ttl: Mapped[Optional[int]] = mapped_column(Integer)
    jarm_fingerprint: Mapped[Optional[str]] = mapped_column(String(100))
    ja3_fingerprint: Mapped[Optional[str]] = mapped_column(String(100))
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    flow_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    flow_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)