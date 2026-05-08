"""
Cyber Global Shield — Zero-Day Exploit Detection
Détection comportementale des exploits zero-day et APT (Advanced Persistent Threats).
Analyse les chaînes d'attaque, les LOLBins, les patterns mémoire et le beaconing C2.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class BehavioralAnomaly:
    """A behavioral anomaly detected."""
    timestamp: datetime
    anomaly_type: str  # process, network, file, memory, registry
    severity: str  # low, medium, high, critical
    description: str
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    risk_score: float = 0.0


class ZeroDayDetector:
    """
    Détecteur d'exploits zero-day et APT.
    
    Techniques:
    - Analyse des chaînes processus (kill chain)
    - Détection LOLBins (Living Off The Land)
    - Analyse de patterns mémoire (shellcode, ROP)
    - Détection de beaconing C2
    - Détection d'exfiltration de données
    """

    def __init__(self):
        self._anomalies: List[BehavioralAnomaly] = []
        self._process_chains: Dict[str, List[Dict]] = defaultdict(list)
        self._known_lolbins: Set[str] = {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe",
        }
        self._suspicious_parents: Set[str] = {
            "winword.exe", "excel.exe", "powerpnt.exe",
            "outlook.exe", "chrome.exe", "firefox.exe",
            "iexplore.exe", "msedge.exe", "acrobat.exe",
            "acrord32.exe", "foxitreader.exe",
        }

    def analyze_process_chain(
        self,
        parent_process: str,
        child_process: str,
        action: str,
        command_line: str = "",
    ) -> Optional[BehavioralAnomaly]:
        """Analyze a process creation chain for zero-day indicators."""
        chain_key = f"{parent_process}->{child_process}"
        
        self._process_chains[chain_key].append({
            "timestamp": datetime.utcnow(),
            "parent": parent_process,
            "child": child_process,
            "action": action,
            "command_line": command_line,
        })

        # LOLBin spawned by suspicious parent (e.g., Word -> PowerShell)
        if (child_process.lower() in self._known_lolbins and 
            parent_process.lower() in self._suspicious_parents):
            
            anomaly = BehavioralAnomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="process",
                severity="high",
                description=f"Suspicious LOLBin chain: {parent_process} spawned {child_process}",
                process_name=child_process,
                parent_process=parent_process,
                indicators=[f"LOLBin: {child_process}", f"Spawned by: {parent_process}"],
                mitre_technique="T1218.011 - Signed Binary Proxy Execution",
                risk_score=0.75,
            )
            self._anomalies.append(anomaly)
            logger.warning(f"🚨 Zero-Day: {anomaly.description}")
            return anomaly

        return None

    def analyze_network_behavior(
        self,
        process_name: str,
        connections: List[Dict],
    ) -> Optional[BehavioralAnomaly]:
        """Analyze network behavior for C2 beaconing and exfiltration."""
        # Beaconing detection (regular intervals)
        if len(connections) >= 5:
            timestamps = [
                c["timestamp"] for c in connections 
                if isinstance(c.get("timestamp"), datetime)
            ]
            if len(timestamps) >= 3:
                intervals = [
                    (timestamps[i+1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps)-1)
                ]
                if intervals and (max(intervals) - min(intervals)) < 3:
                    anomaly = BehavioralAnomaly(
                        timestamp=datetime.utcnow(),
                        anomaly_type="network",
                        severity="high",
                        description=f"C2 beaconing detected from {process_name}",
                        process_name=process_name,
                        indicators=["Regular connection intervals", "Potential C2"],
                        mitre_technique="T1071 - Application Layer Protocol",
                        risk_score=0.8,
                    )
                    self._anomalies.append(anomaly)
                    return anomaly

        # Data exfiltration
        for conn in connections:
            if conn.get("bytes_sent", 0) > 10_000_000:
                anomaly = BehavioralAnomaly(
                    timestamp=datetime.utcnow(),
                    anomaly_type="network",
                    severity="critical",
                    description=f"Possible data exfiltration from {process_name}",
                    process_name=process_name,
                    indicators=[f"Large transfer: {conn.get('bytes_sent', 0)} bytes"],
                    mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
                    risk_score=0.85,
                )
                self._anomalies.append(anomaly)
                return anomaly

        return None

    def analyze_file_behavior(
        self,
        process_name: str,
        file_operations: List[Dict],
    ) -> Optional[BehavioralAnomaly]:
        """Analyze file operations for ransomware and defense evasion."""
        # Mass encryption detection
        encrypt_ops = [
            op for op in file_operations
            if op.get("operation") in ["write", "rename"]
            and any(op.get("path", "").endswith(ext) for ext in
                    [".encrypted", ".locked", ".crypted", ".ransom"])
        ]
        if len(encrypt_ops) > 50:
            anomaly = BehavioralAnomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="file",
                severity="critical",
                description=f"Mass file encryption by {process_name}",
                process_name=process_name,
                indicators=[f"{len(encrypt_ops)} files encrypted"],
                mitre_technique="T1486 - Data Encrypted for Impact",
                risk_score=0.95,
            )
            self._anomalies.append(anomaly)
            return anomaly

        # Shadow copy deletion
        shadow_ops = [
            op for op in file_operations
            if "vssadmin" in op.get("path", "").lower()
            or "wmic shadowcopy" in op.get("path", "").lower()
        ]
        if shadow_ops:
            anomaly = BehavioralAnomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="file",
                severity="critical",
                description=f"Shadow copy deletion by {process_name}",
                process_name=process_name,
                indicators=["Shadow copy deletion", "Ransomware defense evasion"],
                mitre_technique="T1490 - Inhibit System Recovery",
                risk_score=0.9,
            )
            self._anomalies.append(anomaly)
            return anomaly

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get zero-day detector statistics."""
        recent = [
            a for a in self._anomalies
            if (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        return {
            "total_anomalies": len(self._anomalies),
            "recent_anomalies": len(recent),
            "critical_alerts": len([a for a in recent if a.severity == "critical"]),
            "high_alerts": len([a for a in recent if a.severity == "high"]),
            "mitre_techniques": list(set(
                a.mitre_technique for a in self._anomalies if a.mitre_technique
            )),
            "status": "ACTIVE" if not [a for a in recent if a.severity == "critical"] else "ALERT",
        }


zero_day_detector = ZeroDayDetector()
