"""
Cyber Global Shield — Honeypot Intelligence
Système de honeypots intelligents pour détecter et analyser les attaquants en temps réel.
Déploie des leurres (ports, services, credentials, fichiers) pour piéger les menaces.
"""

import os
import json
import socket
import asyncio
import logging
import random
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HoneypotEvent:
    """An interaction with a honeypot."""
    timestamp: datetime
    honeypot_type: str  # port, service, credential, file, api
    src_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: str
    attacker_os: Optional[str] = None
    attacker_tools: List[str] = field(default_factory=list)
    session_id: str = ""
    risk_score: float = 0.0
    country: Optional[str] = None
    isp: Optional[str] = None


class HoneypotService:
    """
    Service de honeypots intelligents.
    - Ports leurres (SSH, RDP, MySQL, etc.)
    - Credentials factices
    - Fichiers sensibles piégés
    - Endpoints API leurres
    - Base de données de leurres
    """

    def __init__(self):
        self._events: List[HoneypotEvent] = []
        self._sessions: Dict[str, Dict] = {}
        self._blocked_ips: Set[str] = set()
        self._honeypot_ports = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            9200: "Elasticsearch",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            1433: "MSSQL",
            5900: "VNC",
            445: "SMB",
        }
        self._fake_credentials = [
            "admin:admin123",
            "root:toor",
            "administrator:P@ssw0rd",
            "sa:sql123",
            "postgres:postgres",
            "backup:backup2024",
            "deploy:deploy123!",
            "jenkins:jenkins",
        ]
        self._fake_files = [
            "passwords.txt",
            "database_backup.sql",
            "aws_credentials.json",
            "ssh_private_key.pem",
            "config_prod.yml",
            "bank_transfer.xlsx",
            "hr_salaries.csv",
            "vpn_config.ovpn",
        ]

    async def start_honeypots(self):
        """Démarrer les écouteurs honeypot."""
        tasks = []
        for port, service in self._honeypot_ports.items():
            tasks.append(self._listen_port(port, service))
        asyncio.gather(*tasks)

    async def _listen_port(self, port: int, service: str):
        """Écouter sur un port leurre."""
        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle_connection(r, w, port, service),
                host="0.0.0.0",
                port=port,
            )
            logger.info(f"🐝 Honeypot {service} listening on port {port}")
            async with server:
                await server.serve_forever()
        except Exception as e:
            logger.debug(f"Honeypot port {port} ({service}): {e}")

    async def _handle_connection(self, reader, writer, port: int, service: str):
        """Gérer une connexion honeypot."""
        client_ip, client_port = writer.get_extra_info("peername")
        session_id = f"hp_{datetime.utcnow().timestamp()}_{client_ip}"

        # Send fake banner
        banners = {
            22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\n",
            23: b"\nTelnet Server Ready\nlogin: ",
            3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",
            3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00",
            5432: b"\x00\x00\x00\x08\x04\xd2\x1f\x2f\x00\x00\x00\x00",
        }
        if port in banners:
            writer.write(banners[port])
            await writer.drain()

        # Collect payload
        payload = b""
        try:
            while True:
                data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                if not data:
                    break
                payload += data
                # Send fake response
                fake_responses = {
                    22: b"Permission denied (publickey,password).\n",
                    23: b"\nPassword: ",
                    3306: b"\x45\x00\x00\x00\x0a\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64",
                }
                if port in fake_responses:
                    writer.write(fake_responses[port])
                    await writer.drain()
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Honeypot connection error: {e}")
        finally:
            writer.close()

        # Analyze the interaction
        event = HoneypotEvent(
            timestamp=datetime.utcnow(),
            honeypot_type="port",
            src_ip=client_ip,
            src_port=client_port,
            dst_port=port,
            protocol="tcp",
            payload=payload.decode("utf-8", errors="replace")[:1000],
            session_id=session_id,
            risk_score=self._calculate_risk(payload, port),
            attacker_tools=self._detect_tools(payload),
        )
        self._events.append(event)
        logger.warning(
            f"🚨 Honeypot hit! {service} from {client_ip}:{client_port} "
            f"(risk: {event.risk_score:.2f})"
        )

        # Auto-block high risk
        if event.risk_score > 0.8:
            self._blocked_ips.add(client_ip)
            logger.critical(f"🛑 Auto-blocked {client_ip} (risk: {event.risk_score:.2f})")

    def _calculate_risk(self, payload: bytes, port: int) -> float:
        """Calculate risk score of an interaction."""
        risk = 0.1  # Base risk
        payload_str = payload.decode("utf-8", errors="replace").lower()

        # High-risk indicators
        high_risk_patterns = [
            "admin", "root", "password", "passwd",
            "exec(", "eval(", "system(", "shell_exec",
            "union select", "drop table", "1=1",
            "../..", "etc/passwd", "win.ini",
            "nmap", "masscan", "sqlmap", "hydra",
            "metasploit", "cve-", "exploit",
            "wget ", "curl ", "powershell",
            "cmd.exe", "/bin/sh", "/bin/bash",
        ]
        for pattern in high_risk_patterns:
            if pattern in payload_str:
                risk += 0.15

        # Port-specific risk
        critical_ports = {22: 0.1, 3389: 0.15, 445: 0.2, 1433: 0.15}
        risk += critical_ports.get(port, 0.05)

        # Payload length indicates scanning depth
        if len(payload) > 500:
            risk += 0.1
        if len(payload) > 2000:
            risk += 0.15

        return min(risk, 1.0)

    def _detect_tools(self, payload: bytes) -> List[str]:
        """Detect attacker tools from payload."""
        tools = []
        payload_str = payload.decode("utf-8", errors="replace").lower()

        tool_signatures = {
            "nmap": ["nmap", "nmap scan", "masscan"],
            "sqlmap": ["sqlmap", "sql injection"],
            "hydra": ["hydra", "medusa"],
            "metasploit": ["metasploit", "msf"],
            "burpsuite": ["burp", "intruder"],
            "gobuster": ["gobuster", "dirbuster"],
            "nikto": ["nikto"],
            "wpscan": ["wpscan"],
            "nessus": ["nessus", "openvas"],
            "python_scanner": ["python-requests", "python-urllib"],
        }

        for tool, signatures in tool_signatures.items():
            if any(sig in payload_str for sig in signatures):
                tools.append(tool)

        return tools

    def get_stats(self) -> Dict[str, Any]:
        """Get honeypot statistics."""
        if not self._events:
            return {"total_events": 0, "blocked_ips": len(self._blocked_ips)}

        total = len(self._events)
        high_risk = sum(1 for e in self._events if e.risk_score > 0.7)
        unique_ips = len(set(e.src_ip for e in self._events))

        # Top attacked ports
        port_stats = {}
        for e in self._events:
            service = self._honeypot_ports.get(e.dst_port, "unknown")
            port_stats[service] = port_stats.get(service, 0) + 1

        # Top attacker IPs
        ip_stats = {}
        for e in self._events:
            ip_stats[e.src_ip] = ip_stats.get(e.src_ip, 0) + 1
        top_attackers = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_events": total,
            "high_risk_events": high_risk,
            "unique_attackers": unique_ips,
            "blocked_ips": len(self._blocked_ips),
            "top_attacked_services": sorted(
                port_stats.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "top_attackers": top_attackers,
            "active_honeypots": len(self._honeypot_ports),
        }

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs."""
        return list(self._blocked_ips)

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked."""
        return ip in self._blocked_ips


# Global honeypot service
honeypot_service = HoneypotService()
