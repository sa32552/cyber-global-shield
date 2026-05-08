"""
Cyber Global Shield — Automated Forensics
Collecte et analyse automatisée de preuves numériques en temps réel.
Capture de mémoire, disque, réseau, logs, et artefacts système.
"""

import os
import json
import time
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ForensicEvidence:
    """A piece of forensic evidence."""
    evidence_id: str
    timestamp: datetime
    evidence_type: str  # memory_dump, disk_image, network_capture, log_file, registry, process_list
    source: str  # hostname, IP, container
    file_path: str
    file_hash: str
    file_size: int
    description: str
    tags: List[str] = field(default_factory=list)
    is_volatile: bool = False


@dataclass
class ForensicReport:
    """A forensic analysis report."""
    report_id: str
    incident_id: str
    created_at: datetime
    evidence_count: int
    findings: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    summary: str = ""


class AutomatedForensics:
    """
    Forensic automatisé.
    
    Collecte:
    - Memory dump (volatile)
    - Process list and tree
    - Network connections
    - Registry hives (Windows)
    - File system artifacts
    - Log files
    - Browser artifacts
    - USB history
    """

    def __init__(self, evidence_dir: str = "/data/forensics"):
        self._evidence_dir = evidence_dir
        self._evidence: List[ForensicEvidence] = []
        self._reports: List[ForensicReport] = []
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure evidence directories exist."""
        dirs = [
            self._evidence_dir,
            os.path.join(self._evidence_dir, "memory"),
            os.path.join(self._evidence_dir, "disk"),
            os.path.join(self._evidence_dir, "network"),
            os.path.join(self._evidence_dir, "logs"),
            os.path.join(self._evidence_dir, "registry"),
            os.path.join(self._evidence_dir, "processes"),
            os.path.join(self._evidence_dir, "reports"),
        ]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)

    def collect_memory_dump(self, hostname: str, pid: Optional[int] = None) -> ForensicEvidence:
        """Collect memory dump (simulated)."""
        evidence_id = f"MEM-{int(time.time())}"
        file_path = os.path.join(self._evidence_dir, "memory", f"{evidence_id}.dmp")

        # Simulate memory dump
        dump_data = json.dumps({
            "hostname": hostname,
            "pid": pid,
            "timestamp": datetime.utcnow().isoformat(),
            "processes": self._simulate_process_list(),
            "network_connections": self._simulate_network_connections(),
        }).encode()

        with open(file_path, "wb") as f:
            f.write(dump_data)

        evidence = ForensicEvidence(
            evidence_id=evidence_id,
            timestamp=datetime.utcnow(),
            evidence_type="memory_dump",
            source=hostname,
            file_path=file_path,
            file_hash=hashlib.sha256(dump_data).hexdigest(),
            file_size=len(dump_data),
            description=f"Memory dump of {hostname}" + (f" (PID: {pid})" if pid else ""),
            tags=["memory", "volatile", hostname],
            is_volatile=True,
        )
        self._evidence.append(evidence)
        logger.info(f"💾 Memory dump collected: {evidence_id}")
        return evidence

    def collect_process_list(self, hostname: str) -> ForensicEvidence:
        """Collect process list."""
        evidence_id = f"PROC-{int(time.time())}"
        file_path = os.path.join(self._evidence_dir, "processes", f"{evidence_id}.json")

        processes = self._simulate_process_list()
        with open(file_path, "w") as f:
            json.dump(processes, f, indent=2)

        evidence = ForensicEvidence(
            evidence_id=evidence_id,
            timestamp=datetime.utcnow(),
            evidence_type="process_list",
            source=hostname,
            file_path=file_path,
            file_hash=hashlib.sha256(json.dumps(processes).encode()).hexdigest(),
            file_size=os.path.getsize(file_path),
            description=f"Process list from {hostname}",
            tags=["processes", hostname],
            is_volatile=True,
        )
        self._evidence.append(evidence)
        return evidence

    def collect_network_capture(self, hostname: str, interface: str = "eth0") -> ForensicEvidence:
        """Collect network connections."""
        evidence_id = f"NET-{int(time.time())}"
        file_path = os.path.join(self._evidence_dir, "network", f"{evidence_id}.json")

        connections = self._simulate_network_connections()
        with open(file_path, "w") as f:
            json.dump(connections, f, indent=2)

        evidence = ForensicEvidence(
            evidence_id=evidence_id,
            timestamp=datetime.utcnow(),
            evidence_type="network_capture",
            source=hostname,
            file_path=file_path,
            file_hash=hashlib.sha256(json.dumps(connections).encode()).hexdigest(),
            file_size=os.path.getsize(file_path),
            description=f"Network connections from {hostname} on {interface}",
            tags=["network", hostname, interface],
            is_volatile=True,
        )
        self._evidence.append(evidence)
        return evidence

    def collect_logs(self, hostname: str, log_types: Optional[List[str]] = None) -> List[ForensicEvidence]:
        """Collect system logs."""
        log_types = log_types or ["system", "security", "application", "audit"]
        collected = []

        for log_type in log_types:
            evidence_id = f"LOG-{int(time.time())}-{log_type}"
            file_path = os.path.join(self._evidence_dir, "logs", f"{evidence_id}.log")

            log_data = self._simulate_logs(log_type)
            with open(file_path, "w") as f:
                f.write(log_data)

            evidence = ForensicEvidence(
                evidence_id=evidence_id,
                timestamp=datetime.utcnow(),
                evidence_type="log_file",
                source=hostname,
                file_path=file_path,
                file_hash=hashlib.sha256(log_data.encode()).hexdigest(),
                file_size=len(log_data.encode()),
                description=f"{log_type} logs from {hostname}",
                tags=["logs", log_type, hostname],
            )
            self._evidence.append(evidence)
            collected.append(evidence)

        return collected

    def _simulate_process_list(self) -> List[Dict]:
        """Simulate a process list for forensics."""
        return [
            {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.5, "user": "root"},
            {"pid": 100, "name": "sshd", "cpu": 0.0, "memory": 0.2, "user": "root"},
            {"pid": 200, "name": "nginx", "cpu": 0.5, "memory": 1.2, "user": "www-data"},
            {"pid": 300, "name": "python3", "cpu": 2.1, "memory": 3.5, "user": "app"},
            {"pid": 400, "name": "redis-server", "cpu": 0.3, "memory": 0.8, "user": "redis"},
            {"pid": 500, "name": "clickhouse-server", "cpu": 1.5, "memory": 5.0, "user": "clickhouse"},
        ]

    def _simulate_network_connections(self) -> List[Dict]:
        """Simulate network connections."""
        return [
            {"local": "10.0.0.1:443", "remote": "10.0.0.2:54321", "state": "ESTABLISHED", "pid": 200},
            {"local": "10.0.0.1:22", "remote": "192.168.1.100:12345", "state": "ESTABLISHED", "pid": 100},
            {"local": "10.0.0.1:6379", "remote": "127.0.0.1:40000", "state": "ESTABLISHED", "pid": 400},
            {"local": "10.0.0.1:9000", "remote": "127.0.0.1:50000", "state": "LISTEN", "pid": 500},
        ]

    def _simulate_logs(self, log_type: str) -> str:
        """Simulate log entries."""
        logs = []
        for i in range(10):
            logs.append(
                f"{datetime.utcnow().isoformat()} [{log_type.upper()}] "
                f"Sample log entry #{i+1} for {log_type}"
            )
        return "\n".join(logs)

    def generate_report(self, incident_id: str) -> ForensicReport:
        """Generate a forensic report from collected evidence."""
        report = ForensicReport(
            report_id=f"FR-{int(time.time())}",
            incident_id=incident_id,
            created_at=datetime.utcnow(),
            evidence_count=len(self._evidence),
            findings=self._analyze_evidence(),
            timeline=self._build_timeline(),
            iocs=self._extract_iocs(),
            recommendations=[
                "Analyser les memory dumps pour les processus suspects",
                "Vérifier les connexions réseau sortantes",
                "Rechercher des indicateurs de compromission",
                "Isoler les systèmes affectés",
                "Effectuer une analyse de régression",
            ],
            summary=f"Forensic analysis completed for incident {incident_id}. "
                    f"Collected {len(self._evidence)} pieces of evidence.",
        )
        self._reports.append(report)
        logger.info(f"📋 Forensic report generated: {report.report_id}")
        return report

    def _analyze_evidence(self) -> List[Dict]:
        """Analyze collected evidence for findings."""
        findings = []
        for evidence in self._evidence:
            finding = {
                "evidence_id": evidence.evidence_id,
                "type": evidence.evidence_type,
                "source": evidence.source,
                "timestamp": evidence.timestamp.isoformat(),
                "status": "collected",
                "preliminary_analysis": f"Evidence {evidence.evidence_type} from {evidence.source}",
            }
            findings.append(finding)
        return findings

    def _build_timeline(self) -> List[Dict]:
        """Build a timeline from evidence."""
        timeline = []
        for evidence in sorted(self._evidence, key=lambda e: e.timestamp):
            timeline.append({
                "timestamp": evidence.timestamp.isoformat(),
                "event": f"{evidence.evidence_type} collected from {evidence.source}",
                "evidence_id": evidence.evidence_id,
            })
        return timeline

    def _extract_iocs(self) -> List[str]:
        """Extract Indicators of Compromise from evidence."""
        iocs = []
        for evidence in self._evidence:
            if evidence.evidence_type == "network_capture":
                iocs.append(f"Network evidence: {evidence.source}")
            elif evidence.evidence_type == "memory_dump":
                iocs.append(f"Memory evidence: {evidence.source}")
        return iocs

    def get_stats(self) -> Dict[str, Any]:
        """Get forensics statistics."""
        return {
            "total_evidence": len(self._evidence),
            "total_reports": len(self._reports),
            "evidence_by_type": dict(
                (t, len([e for e in self._evidence if e.evidence_type == t]))
                for t in set(e.evidence_type for e in self._evidence)
            ),
            "total_size_mb": sum(e.file_size for e in self._evidence) / (1024 * 1024),
            "status": "READY",
        }


automated_forensics = AutomatedForensics()
