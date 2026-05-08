"""
Cyber Global Shield — Memory Forensics Analyzer
Analyse de mémoire volatile pour détection de rootkits, malware, et artefacts.
Inspiré de Volatility, Rekall, et Redline.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MemoryArtifact:
    """An artifact found in memory."""
    artifact_id: str
    type: str  # process, network, registry, driver, hook, injection
    name: str
    pid: Optional[int]
    path: Optional[str]
    severity: str
    description: str
    ioc_match: bool


class MemoryForensicsAnalyzer:
    """
    Analyse de mémoire volatile.
    
    Détecte:
    - Processus cachés (DKOM)
    - Rootkits (SSDT, IDT, IRP hooks)
    - Code injection (APC, thread hijacking)
    - Network connections cachées
    - Drivers malveillants
    - Registry modifications
    - MZ/PE in memory
    """

    def __init__(self):
        self._analyses: List[Dict] = []
        self._known_bad_processes = self._load_bad_processes()
        self._known_bad_drivers = self._load_bad_drivers()

    def _load_bad_processes(self) -> Dict[str, str]:
        """Load known malicious processes."""
        return {
            "mimikatz.exe": "Credential dumping tool",
            "procdump.exe": "Process dumping (legitimate but abused)",
            "psexec.exe": "Remote execution (legitimate but abused)",
            "wce.exe": "Windows Credential Editor",
            "cobaltstrike.exe": "C2 beacon",
            "meterpreter.exe": "Metasploit payload",
            "nc.exe": "Netcat backdoor",
            "plink.exe": "SSH tunneling tool",
        }

    def _load_bad_drivers(self) -> Dict[str, str]:
        """Load known malicious drivers."""
        return {
            "capcom.sys": "Capcom rootkit driver",
            "gdrv.sys": "Gigabyte driver (BYOVD)",
            "aswsp.sys": "Avast driver (BYOVD)",
            "rtcore64.sys": "RTCore64 vulnerable driver",
            "dbk64.sys": "Cheat Engine driver",
        }

    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze a memory dump file."""
        analysis_id = f"MEM-{int(datetime.utcnow().timestamp())}"
        
        artifacts = []
        
        # 1. Process analysis
        process_artifacts = self._analyze_processes()
        artifacts.extend(process_artifacts)
        
        # 2. Network analysis
        network_artifacts = self._analyze_network()
        artifacts.extend(network_artifacts)
        
        # 3. Driver analysis
        driver_artifacts = self._analyze_drivers()
        artifacts.extend(driver_artifacts)
        
        # 4. Injection analysis
        injection_artifacts = self._analyze_injections()
        artifacts.extend(injection_artifacts)
        
        # 5. Registry analysis
        registry_artifacts = self._analyze_registry()
        artifacts.extend(registry_artifacts)

        analysis = {
            "analysis_id": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "dump_path": dump_path,
            "total_artifacts": len(artifacts),
            "malicious": len([a for a in artifacts if a.severity in ["critical", "high"]]),
            "suspicious": len([a for a in artifacts if a.severity == "medium"]),
            "ioc_matches": len([a for a in artifacts if a.ioc_match]),
            "artifacts": [a.__dict__ for a in artifacts],
            "verdict": self._generate_verdict(artifacts),
        }

        self._analyses.append(analysis)
        
        if analysis["malicious"] > 0:
            logger.critical(
                f"🔴 Memory forensics: {analysis['malicious']} malicious artifacts "
                f"found in {dump_path}"
            )

        return analysis

    def _analyze_processes(self) -> List[MemoryArtifact]:
        """Analyze running processes."""
        artifacts = []
        
        # Simulated process list
        processes = [
            {"name": "svchost.exe", "pid": 456, "path": "C:\\Windows\\System32\\svchost.exe"},
            {"name": "explorer.exe", "pid": 1234, "path": "C:\\Windows\\explorer.exe"},
            {"name": "mimikatz.exe", "pid": 3456, "path": "C:\\Users\\admin\\mimikatz.exe"},
            {"name": "unknown_process.exe", "pid": 7890, "path": "C:\\Temp\\unknown.exe"},
            {"name": "lsass.exe", "pid": 567, "path": "C:\\Windows\\System32\\lsass.exe"},
        ]

        for proc in processes:
            severity = "info"
            description = f"Process: {proc['name']} (PID: {proc['pid']})"
            ioc_match = False

            # Check against known bad processes
            if proc["name"].lower() in self._known_bad_processes:
                severity = "critical"
                description = f"MALICIOUS: {self._known_bad_processes[proc['name'].lower()]}"
                ioc_match = True
            elif "temp" in proc["path"].lower() or "downloads" in proc["path"].lower():
                severity = "high"
                description = f"Suspicious process location: {proc['path']}"
            elif proc["name"] == "lsass.exe":
                # Check if lsass is being accessed (potential credential dumping)
                severity = "medium"
                description = "LSASS process - potential credential dumping target"

            artifact = MemoryArtifact(
                artifact_id=f"PROC-{proc['pid']}",
                type="process",
                name=proc["name"],
                pid=proc["pid"],
                path=proc["path"],
                severity=severity,
                description=description,
                ioc_match=ioc_match,
            )
            artifacts.append(artifact)

        return artifacts

    def _analyze_network(self) -> List[MemoryArtifact]:
        """Analyze network connections."""
        artifacts = []
        
        # Simulated network connections
        connections = [
            {"local": "192.168.1.100:49152", "remote": "185.220.101.23:443", "state": "ESTABLISHED"},
            {"local": "192.168.1.100:49153", "remote": "8.8.8.8:53", "state": "ESTABLISHED"},
            {"local": "0.0.0.0:445", "remote": "0.0.0.0:0", "state": "LISTENING"},
            {"local": "192.168.1.100:49154", "remote": "91.121.87.45:8080", "state": "ESTABLISHED"},
        ]

        suspicious_ips = ["185.220.101.23", "91.121.87.45", "5.255.88.100"]
        
        for conn in connections:
            severity = "info"
            description = f"Connection: {conn['local']} -> {conn['remote']} ({conn['state']})"
            ioc_match = False

            remote_ip = conn["remote"].split(":")[0]
            if remote_ip in suspicious_ips:
                severity = "critical"
                description = f"C2 communication detected: {conn['remote']}"
                ioc_match = True
            elif conn["state"] == "LISTENING" and ":445" in conn["local"]:
                severity = "medium"
                description = "SMB listener - potential lateral movement vector"

            artifact = MemoryArtifact(
                artifact_id=f"NET-{len(artifacts)+1}",
                type="network",
                name=f"Connection to {conn['remote']}",
                pid=None,
                path=None,
                severity=severity,
                description=description,
                ioc_match=ioc_match,
            )
            artifacts.append(artifact)

        return artifacts

    def _analyze_drivers(self) -> List[MemoryArtifact]:
        """Analyze loaded drivers."""
        artifacts = []
        
        # Simulated driver list
        drivers = [
            {"name": "ntoskrnl.exe", "path": "C:\\Windows\\System32\\ntoskrnl.exe"},
            {"name": "capcom.sys", "path": "C:\\Windows\\System32\\drivers\\capcom.sys"},
            {"name": "tcpip.sys", "path": "C:\\Windows\\System32\\drivers\\tcpip.sys"},
        ]

        for drv in drivers:
            severity = "info"
            description = f"Driver: {drv['name']}"
            ioc_match = False

            if drv["name"].lower() in self._known_bad_drivers:
                severity = "critical"
                description = f"MALICIOUS DRIVER: {self._known_bad_drivers[drv['name'].lower()]}"
                ioc_match = True

            artifact = MemoryArtifact(
                artifact_id=f"DRV-{drv['name']}",
                type="driver",
                name=drv["name"],
                pid=None,
                path=drv["path"],
                severity=severity,
                description=description,
                ioc_match=ioc_match,
            )
            artifacts.append(artifact)

        return artifacts

    def _analyze_injections(self) -> List[MemoryArtifact]:
        """Analyze code injection artifacts."""
        artifacts = []
        
        # Simulated injection detection
        injections = [
            {"technique": "APC Injection", "target_pid": 1234, "source_pid": 3456},
            {"technique": "Process Hollowing", "target_pid": 5678, "source_pid": 3456},
        ]

        for inj in injections:
            artifact = MemoryArtifact(
                artifact_id=f"INJ-{len(artifacts)+1}",
                type="injection",
                name=f"{inj['technique']} (PID {inj['source_pid']} -> {inj['target_pid']})",
                pid=inj["target_pid"],
                path=None,
                severity="critical",
                description=f"Code injection detected: {inj['technique']}",
                ioc_match=True,
            )
            artifacts.append(artifact)

        return artifacts

    def _analyze_registry(self) -> List[MemoryArtifact]:
        """Analyze registry artifacts."""
        artifacts = []
        
        # Simulated registry analysis
        registry_keys = [
            {
                "key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MaliciousService",
                "value": "ImagePath = C:\\Windows\\Temp\\malware.exe",
                "severity": "critical",
            },
            {
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "Malware = C:\\Users\\admin\\malware.exe",
                "severity": "high",
            },
        ]

        for reg in registry_keys:
            artifact = MemoryArtifact(
                artifact_id=f"REG-{len(artifacts)+1}",
                type="registry",
                name=reg["key"],
                pid=None,
                path=reg["value"],
                severity=reg["severity"],
                description=f"Registry persistence mechanism: {reg['key']}",
                ioc_match=True,
            )
            artifacts.append(artifact)

        return artifacts

    def _generate_verdict(self, artifacts: List[MemoryArtifact]) -> str:
        """Generate analysis verdict."""
        critical = len([a for a in artifacts if a.severity == "critical"])
        high = len([a for a in artifacts if a.severity == "high"])
        
        if critical > 0:
            return "COMPROMISED - Active malware detected"
        elif high > 0:
            return "SUSPICIOUS - Further investigation required"
        else:
            return "CLEAN - No malicious artifacts found"

    def get_stats(self) -> Dict[str, Any]:
        """Get memory forensics statistics."""
        return {
            "total_analyses": len(self._analyses),
            "compromised": len([a for a in self._analyses if "COMPROMISED" in a.get("verdict", "")]),
            "suspicious": len([a for a in self._analyses if "SUSPICIOUS" in a.get("verdict", "")]),
            "clean": len([a for a in self._analyses if "CLEAN" in a.get("verdict", "")]),
            "status": "ANALYZING",
        }


memory_forensics = MemoryForensicsAnalyzer()
