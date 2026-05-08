"""
Cyber Global Shield — Deep Packet Inspection (DPI)
Analyse réseau en temps réel avec détection de protocoles, patterns malveillants,
exfiltration de données et tunnels cachés.
"""

import os
import json
import struct
import logging
import socket
from typing import Optional, Dict, Any, List, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class PacketAnalysis:
    """Analysis result of a network packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, DNS, HTTP, TLS
    payload_size: int
    detected_protocols: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    is_encrypted: bool = False
    is_tunnel: bool = False
    risk_score: float = 0.0
    payload_preview: str = ""


@dataclass
class NetworkSession:
    """A network session with analysis."""
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    packets: List[PacketAnalysis] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_received: int = 0
    is_suspicious: bool = False
    risk_score: float = 0.0


class DeepPacketInspector:
    """
    Deep Packet Inspection engine.
    
    Détecte:
    - Protocoles non standards sur ports standards
    - Tunnels DNS/HTTP/ICMP
    - Exfiltration de données
    - Patterns de C2
    - Port knocking
    - DNS tunneling
    """

    def __init__(self):
        self._sessions: Dict[str, NetworkSession] = {}
        self._suspicious_ips: Set[str] = set()
        self._known_c2_patterns = self._load_c2_patterns()
        self._dns_queries: Dict[str, List[str]] = defaultdict(list)

    def _load_c2_patterns(self) -> Dict[str, List[str]]:
        """Load known C2 communication patterns."""
        return {
            "dns_tunnel": [
                "long_subdomain", "base64_subdomain",
                "txt_record_exfil", "high_frequency_queries",
            ],
            "http_beacon": [
                "regular_intervals", "user_agent_rotation",
                "custom_headers", "encrypted_payload",
            ],
            "icmp_tunnel": [
                "large_icmp_packets", "abnormal_icmp_types",
                "high_icmp_frequency",
            ],
            "websocket_c2": [
                "long_lived_connections", "binary_frames",
                "irregular_heartbeats",
            ],
        }

    def analyze_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload: bytes,
    ) -> PacketAnalysis:
        """Analyze a single network packet."""
        analysis = PacketAnalysis(
            timestamp=datetime.utcnow(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload_size=len(payload),
            payload_preview=payload[:200].decode("utf-8", errors="replace"),
        )

        # Protocol detection
        detected = self._detect_protocols(payload, dst_port)
        analysis.detected_protocols = detected

        # Suspicious pattern detection
        suspicious = self._detect_suspicious_patterns(payload, protocol, dst_port)
        analysis.suspicious_patterns = suspicious

        # Encryption detection
        analysis.is_encrypted = self._detect_encryption(payload)

        # Tunnel detection
        analysis.is_tunnel = self._detect_tunnel(payload, protocol, dst_port)

        # Risk scoring
        analysis.risk_score = self._calculate_packet_risk(analysis)

        # Update session
        self._update_session(analysis)

        return analysis

    def _detect_protocols(self, payload: bytes, port: int) -> List[str]:
        """Detect protocols in packet payload."""
        protocols = []
        payload_str = payload[:100].decode("utf-8", errors="replace")

        # HTTP detection
        if any(method in payload_str for method in ["GET ", "POST ", "PUT ", "DELETE "]):
            protocols.append("HTTP")
            if "Host:" in payload_str:
                protocols.append("HTTP/1.1")

        # DNS detection
        if port == 53 or len(payload) > 0:
            try:
                if len(payload) >= 12:  # DNS header minimum
                    # Check DNS header flags
                    flags = struct.unpack("!H", payload[2:4])[0]
                    if flags & 0x8000:  # QR bit
                        protocols.append("DNS")
            except (struct.error, IndexError):
                pass

        # TLS detection
        if len(payload) >= 1 and payload[0] == 0x16:  # TLS handshake
            protocols.append("TLS")
            if len(payload) >= 5:
                version = payload[1:3]
                if version == b"\x03\x03":
                    protocols.append("TLSv1.2")
                elif version == b"\x03\x04":
                    protocols.append("TLSv1.3")

        # SSH detection
        if b"SSH-" in payload[:50]:
            protocols.append("SSH")

        # SMB detection
        if payload[:4] == b"\xff\x53\x4d\x42":
            protocols.append("SMB")

        return protocols

    def _detect_suspicious_patterns(self, payload: bytes, protocol: str, port: int) -> List[str]:
        """Detect suspicious patterns in packet."""
        patterns = []
        payload_str = payload.decode("utf-8", errors="replace").lower()

        # SQL injection attempts
        sql_patterns = [
            "union select", "drop table", "1=1", "1=2",
            "admin'--", "or 1=1", "exec xp_",
        ]
        for pattern in sql_patterns:
            if pattern in payload_str:
                patterns.append(f"SQL_INJECTION: {pattern}")
                break

        # Command injection
        cmd_patterns = [
            "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
            "wget ", "curl ", "nc -e", "bash -i",
        ]
        for pattern in cmd_patterns:
            if pattern in payload_str:
                patterns.append(f"CMD_INJECTION: {pattern}")
                break

        # Path traversal
        if "../" in payload_str or "..\\" in payload_str:
            patterns.append("PATH_TRAVERSAL")

        # Base64 encoded payloads (potential C2)
        if len(payload) > 100:
            b64_chars = sum(1 for c in payload_str if c.isalnum() or c in "+/=")
            if b64_chars > len(payload_str) * 0.8:
                patterns.append("BASE64_ENCODED_PAYLOAD")

        # Port scan detection
        if protocol == "TCP" and len(payload) == 0:
            patterns.append("PORT_SCAN_PROBE")

        return patterns

    def _detect_encryption(self, payload: bytes) -> bool:
        """Detect if payload is encrypted using entropy analysis."""
        if len(payload) < 10:
            return False

        # Shannon entropy
        entropy = 0.0
        for x in range(256):
            p_x = payload.count(x) / len(payload)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)

        return entropy > 7.0

    def _detect_tunnel(self, payload: bytes, protocol: str, port: int) -> bool:
        """Detect tunneling attempts."""
        payload_str = payload.decode("utf-8", errors="replace").lower()

        # DNS tunneling indicators
        if port == 53:
            # Long subdomain queries
            if len(payload) > 200:
                return True
            # High entropy subdomains
            if self._detect_encryption(payload):
                return True

        # HTTP tunneling
        if port in [80, 443, 8080]:
            # CONNECT method (proxy tunneling)
            if b"CONNECT" in payload[:100]:
                return True
            # Non-standard headers
            if b"X-Tunnel" in payload or b"Proxy-Authorization" in payload:
                return True

        # ICMP tunneling
        if protocol == "ICMP" and len(payload) > 100:
            return True

        return False

    def _calculate_packet_risk(self, analysis: PacketAnalysis) -> float:
        """Calculate risk score for a packet."""
        risk = 0.0

        # Suspicious patterns increase risk
        risk += len(analysis.suspicious_patterns) * 0.2

        # Tunneling is high risk
        if analysis.is_tunnel:
            risk += 0.5

        # Encrypted on non-standard ports
        if analysis.is_encrypted and analysis.dst_port not in [443, 22, 993, 636]:
            risk += 0.3

        # Protocol mismatch (e.g., HTTP on SSH port)
        if "HTTP" in analysis.detected_protocols and analysis.dst_port == 22:
            risk += 0.4

        return min(risk, 1.0)

    def _update_session(self, analysis: PacketAnalysis):
        """Update network session with packet analysis."""
        session_key = f"{analysis.src_ip}:{analysis.src_port}-{analysis.dst_ip}:{analysis.dst_port}"

        if session_key not in self._sessions:
            self._sessions[session_key] = NetworkSession(
                session_id=session_key,
                src_ip=analysis.src_ip,
                dst_ip=analysis.dst_ip,
                src_port=analysis.src_port,
                dst_port=analysis.dst_port,
                protocol=analysis.protocol,
                start_time=analysis.timestamp,
            )

        session = self._sessions[session_key]
        session.packets.append(analysis)
        session.bytes_sent += analysis.payload_size
        session.end_time = analysis.timestamp

        # Update session risk
        if analysis.risk_score > 0.5:
            session.is_suspicious = True
        session.risk_score = max(session.risk_score, analysis.risk_score)

        # Track suspicious IPs
        if analysis.risk_score > 0.7:
            self._suspicious_ips.add(analysis.src_ip)

    def get_suspicious_sessions(self) -> List[NetworkSession]:
        """Get all suspicious network sessions."""
        return [s for s in self._sessions.values() if s.is_suspicious]

    def get_stats(self) -> Dict[str, Any]:
        """Get DPI statistics."""
        total_sessions = len(self._sessions)
        suspicious = self.get_suspicious_sessions()
        total_packets = sum(len(s.packets) for s in self._sessions.values())

        return {
            "total_sessions": total_sessions,
            "suspicious_sessions": len(suspicious),
            "total_packets_analyzed": total_packets,
            "suspicious_ips": len(self._suspicious_ips),
            "avg_session_risk": (
                sum(s.risk_score for s in self._sessions.values()) / total_sessions
                if total_sessions > 0 else 0.0
            ),
            "top_protocols": self._get_top_protocols(),
            "status": "MONITORING",
        }

    def _get_top_protocols(self) -> List[Tuple[str, int]]:
        """Get most detected protocols."""
        protocol_count = defaultdict(int)
        for session in self._sessions.values():
            for packet in session.packets:
                for proto in packet.detected_protocols:
                    protocol_count[proto] += 1
        return sorted(protocol_count.items(), key=lambda x: x[1], reverse=True)[:5]


deep_packet_inspector = DeepPacketInspector()
