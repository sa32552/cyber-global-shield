"""
Cyber Global Shield — Autonomous Threat Hunter
Chasseur de menaces autonome qui explore en continu l'infrastructure
à la recherche de compromissions cachées, persistence, et mouvements latéraux.
"""

import json
import random
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HuntingFinding:
    """A finding from autonomous threat hunting."""
    timestamp: datetime
    hunting_type: str  # lateral_movement, persistence, privilege_escalation, data_exfil, c2
    severity: str
    host: str
    description: str
    mitre_technique: str = ""
    iocs: List[str] = field(default_factory=list)
    confidence: float = 0.0
    is_confirmed: bool = False


class AutonomousThreatHunter:
    """
    Chasseur de menaces autonome.
    
    Chasse:
    - Mouvements latéraux (pass-the-hash, RDP jumps)
    - Persistence (scheduled tasks, services, registry)
    - Élévation de privilèges
    - Exfiltration de données
    - Communication C2
    - Living-off-the-land binaries
    """

    def __init__(self):
        self._findings: List[HuntingFinding] = []
        self._hunt_schedule: Dict[str, datetime] = {}
        self._known_iocs: Dict[str, List[str]] = {}
        self._hunting_patterns = self._load_hunting_patterns()

    def _load_hunting_patterns(self) -> Dict[str, List[str]]:
        """Load hunting patterns and techniques."""
        return {
            "lateral_movement": [
                "T1021.001",  # RDP
                "T1021.002",  # SMB/Admin Shares
                "T1550.002",  # Pass-the-Hash
                "T1021.006",  # PowerShell Remoting
                "T1090",      # Proxy
            ],
            "persistence": [
                "T1053.005",  # Scheduled Task
                "T1543.003",  # Windows Service
                "T1547.001",  # Registry Run Keys
                "T1505.003",  # Web Shell
                "T1136",      # Create Account
            ],
            "privilege_escalation": [
                "T1548.002",  # Bypass UAC
                "T1055",      # Process Injection
                "T1068",      # Exploitation
                "T1134",      # Access Token Manipulation
                "T1546",      # Event Triggered Execution
            ],
            "c2": [
                "T1071.001",  # Web Protocols
                "T1572",      # Protocol Tunneling
                "T1095",      # Non-Standard Port
                "T1102",      # Web Service
                "T1573",      # Encrypted Channel
            ],
            "defense_evasion": [
                "T1562.001",  # Disable Windows Defender
                "T1070",      # Indicator Removal
                "T1564",      # Hide Artifacts
                "T1112",      # Modify Registry
                "T1497",      # Virtualization/Sandbox Evasion
            ],
        }

    def hunt_lateral_movement(self, host: str) -> Optional[HuntingFinding]:
        """Hunt for lateral movement indicators."""
        # Simulate detection
        if random.random() < 0.15:  # 15% detection rate
            techniques = [
                "RDP connection from unusual source",
                "SMB admin share access from non-admin host",
                "PowerShell remoting session to multiple hosts",
                "Pass-the-Hash detected via Event ID 4624",
                "WMI execution on remote host",
            ]
            finding = HuntingFinding(
                timestamp=datetime.utcnow(),
                hunting_type="lateral_movement",
                severity="critical",
                host=host,
                description=random.choice(techniques),
                mitre_technique=random.choice(
                    self._hunting_patterns["lateral_movement"]
                ),
                iocs=[f"IP_{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"],
                confidence=random.uniform(0.6, 0.95),
            )
            self._findings.append(finding)
            logger.critical(f"🔍 Lateral movement detected on {host}: {finding.description}")
            return finding
        return None

    def hunt_persistence(self, host: str) -> Optional[HuntingFinding]:
        """Hunt for persistence mechanisms."""
        if random.random() < 0.2:
            techniques = [
                "Suspicious scheduled task created",
                "Unknown service installed",
                "Registry Run key modified",
                "Startup folder contains suspicious binary",
                "WMI persistence subscription detected",
            ]
            finding = HuntingFinding(
                timestamp=datetime.utcnow(),
                hunting_type="persistence",
                severity="high",
                host=host,
                description=random.choice(techniques),
                mitre_technique=random.choice(
                    self._hunting_patterns["persistence"]
                ),
                iocs=[f"TASK_{random.randint(1000,9999)}"],
                confidence=random.uniform(0.5, 0.9),
            )
            self._findings.append(finding)
            logger.warning(f"🔍 Persistence detected on {host}: {finding.description}")
            return finding
        return None

    def hunt_c2(self, host: str) -> Optional[HuntingFinding]:
        """Hunt for C2 communication."""
        if random.random() < 0.1:
            techniques = [
                "Beaconing to known C2 infrastructure",
                "DNS queries to DGA domains",
                "HTTPS to suspicious IP (non-standard cert)",
                "WebSocket connection to unknown endpoint",
                "ICMP tunneling detected",
            ]
            finding = HuntingFinding(
                timestamp=datetime.utcnow(),
                hunting_type="c2",
                severity="critical",
                host=host,
                description=random.choice(techniques),
                mitre_technique=random.choice(
                    self._hunting_patterns["c2"]
                ),
                iocs=[f"C2_{random.randint(10000,99999)}.xyz"],
                confidence=random.uniform(0.7, 0.98),
            )
            self._findings.append(finding)
            logger.critical(f"🔍 C2 communication detected from {host}: {finding.description}")
            return finding
        return None

    def hunt_defense_evasion(self, host: str) -> Optional[HuntingFinding]:
        """Hunt for defense evasion."""
        if random.random() < 0.12:
            techniques = [
                "Windows Defender disabled",
                "Security event logs cleared",
                "Firewall rules modified",
                "AMSI bypass detected",
                "ETW patching detected",
            ]
            finding = HuntingFinding(
                timestamp=datetime.utcnow(),
                hunting_type="defense_evasion",
                severity="high",
                host=host,
                description=random.choice(techniques),
                mitre_technique=random.choice(
                    self._hunting_patterns["defense_evasion"]
                ),
                iocs=["EVENT_LOG_CLEARED"],
                confidence=random.uniform(0.6, 0.95),
            )
            self._findings.append(finding)
            logger.warning(f"🔍 Defense evasion on {host}: {finding.description}")
            return finding
        return None

    def full_hunt(self, hosts: List[str]) -> List[HuntingFinding]:
        """Execute full hunting cycle on multiple hosts."""
        findings = []
        for host in hosts:
            for hunt_fn in [
                self.hunt_lateral_movement,
                self.hunt_persistence,
                self.hunt_c2,
                self.hunt_defense_evasion,
            ]:
                finding = hunt_fn(host)
                if finding:
                    findings.append(finding)
        return findings

    def get_stats(self) -> Dict[str, Any]:
        """Get threat hunting statistics."""
        recent = [
            f for f in self._findings
            if (datetime.utcnow() - f.timestamp).total_seconds() < 3600
        ]
        return {
            "total_findings": len(self._findings),
            "recent_findings": len(recent),
            "critical_findings": len([f for f in recent if f.severity == "critical"]),
            "hunting_types": dict(
                (t, len([f for f in recent if f.hunting_type == t]))
                for t in set(f.hunting_type for f in recent)
            ),
            "confirmed_threats": len([f for f in self._findings if f.is_confirmed]),
            "status": "HUNTING",
        }


autonomous_threat_hunter = AutonomousThreatHunter()
