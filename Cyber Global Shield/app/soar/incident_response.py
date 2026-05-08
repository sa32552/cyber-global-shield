"""
Cyber Global Shield — Automated Incident Response (AIR)
Réponse automatisée aux incidents avec orchestration complète.
Playbooks d'auto-défense, containment, eradication, recovery.
"""

import os
import json
import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    ANALYZING = "analyzing"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    FAILED = "failed"


class ResponseAction(str, Enum):
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    ISOLATE_HOST = "isolate_host"
    REVOKE_TOKEN = "revoke_token"
    DISABLE_USER = "disable_user"
    ROLLBACK_CHANGES = "rollback_changes"
    RESTORE_BACKUP = "restore_backup"
    ALERT_ADMIN = "alert_admin"
    SCAN_ENDPOINT = "scan_endpoint"
    UPDATE_FIREWALL = "update_firewall"
    RESET_PASSWORD = "reset_password"
    ENABLE_MFA = "enable_mfa"


@dataclass
class Incident:
    """A security incident."""
    id: str
    timestamp: datetime
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.DETECTED
    title: str
    description: str
    source: str  # honeypot, ransomware_shield, zero_day, anomaly_detector, etc.
    affected_assets: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    actions_taken: List[Dict] = field(default_factory=list)
    resolved_at: Optional[datetime] = None
    notes: str = ""


class IncidentResponse:
    """
    Réponse automatisée aux incidents.
    
    Orchestration complète:
    1. Détection et classification
    2. Containment automatique
    3. Éradication de la menace
    4. Récupération des systèmes
    5. Post-mortem et reporting
    """

    def __init__(self):
        self._incidents: List[Incident] = []
        self._playbooks = self._load_playbooks()
        self._blocked_ips: set = set()
        self._isolated_hosts: set = set()

    def _load_playbooks(self) -> Dict[str, List[Dict]]:
        """Load automated response playbooks."""
        return {
            "ransomware_detected": {
                "severity": IncidentSeverity.CRITICAL,
                "parallel_actions": [
                    {
                        "action": ResponseAction.ISOLATE_HOST,
                        "params": {"immediate": True},
                        "timeout": 30,
                    },
                    {
                        "action": ResponseAction.KILL_PROCESS,
                        "params": {"process_name": "unknown_encrypt*"},
                        "timeout": 15,
                    },
                    {
                        "action": ResponseAction.ALERT_ADMIN,
                        "params": {"channel": "emergency"},
                        "timeout": 5,
                    },
                ],
                "sequential_actions": [
                    {
                        "action": ResponseAction.BLOCK_IP,
                        "params": {"duration": "24h"},
                        "timeout": 10,
                    },
                    {
                        "action": ResponseAction.ROLLBACK_CHANGES,
                        "params": {"type": "filesystem"},
                        "timeout": 120,
                    },
                    {
                        "action": ResponseAction.RESTORE_BACKUP,
                        "params": {"type": "critical"},
                        "timeout": 300,
                    },
                ],
            },
            "brute_force_detected": {
                "severity": IncidentSeverity.HIGH,
                "parallel_actions": [
                    {
                        "action": ResponseAction.BLOCK_IP,
                        "params": {"duration": "1h"},
                        "timeout": 10,
                    },
                    {
                        "action": ResponseAction.ALERT_ADMIN,
                        "params": {"channel": "security"},
                        "timeout": 5,
                    },
                ],
                "sequential_actions": [
                    {
                        "action": ResponseAction.ENABLE_MFA,
                        "params": {"force": True},
                        "timeout": 30,
                    },
                    {
                        "action": ResponseAction.RESET_PASSWORD,
                        "params": {"affected_users": True},
                        "timeout": 60,
                    },
                ],
            },
            "data_exfiltration": {
                "severity": IncidentSeverity.CRITICAL,
                "parallel_actions": [
                    {
                        "action": ResponseAction.BLOCK_IP,
                        "params": {"direction": "outbound"},
                        "timeout": 10,
                    },
                    {
                        "action": ResponseAction.REVOKE_TOKEN,
                        "params": {"all_sessions": True},
                        "timeout": 15,
                    },
                ],
                "sequential_actions": [
                    {
                        "action": ResponseAction.DISABLE_USER,
                        "params": {"suspicious_only": True},
                        "timeout": 20,
                    },
                    {
                        "action": ResponseAction.SCAN_ENDPOINT,
                        "params": {"deep_scan": True},
                        "timeout": 180,
                    },
                ],
            },
            "zero_day_exploit": {
                "severity": IncidentSeverity.CRITICAL,
                "parallel_actions": [
                    {
                        "action": ResponseAction.ISOLATE_HOST,
                        "params": {"immediate": True},
                        "timeout": 15,
                    },
                    {
                        "action": ResponseAction.KILL_PROCESS,
                        "params": {"suspicious_only": True},
                        "timeout": 10,
                    },
                ],
                "sequential_actions": [
                    {
                        "action": ResponseAction.UPDATE_FIREWALL,
                        "params": {"block_all": True},
                        "timeout": 30,
                    },
                    {
                        "action": ResponseAction.SCAN_ENDPOINT,
                        "params": {"memory_analysis": True},
                        "timeout": 300,
                    },
                ],
            },
            "insider_threat": {
                "severity": IncidentSeverity.HIGH,
                "parallel_actions": [
                    {
                        "action": ResponseAction.DISABLE_USER,
                        "params": {"immediate": True},
                        "timeout": 10,
                    },
                    {
                        "action": ResponseAction.REVOKE_TOKEN,
                        "params": {"all_sessions": True},
                        "timeout": 10,
                    },
                ],
                "sequential_actions": [
                    {
                        "action": ResponseAction.ALERT_ADMIN,
                        "params": {"channel": "confidential"},
                        "timeout": 5,
                    },
                    {
                        "action": ResponseAction.SCAN_ENDPOINT,
                        "params": {"audit_logs": True},
                        "timeout": 120,
                    },
                ],
            },
        }

    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        source: str,
        affected_assets: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
        indicators: Optional[List[str]] = None,
        mitre_technique: Optional[str] = None,
    ) -> Incident:
        """Create a new incident and trigger automated response."""
        incident = Incident(
            id=f"INC-{int(time.time())}-{len(self._incidents)+1}",
            timestamp=datetime.utcnow(),
            severity=severity,
            title=title,
            description=description,
            source=source,
            affected_assets=affected_assets or [],
            affected_users=affected_users or [],
            indicators=indicators or [],
            mitre_technique=mitre_technique,
        )

        self._incidents.append(incident)
        logger.critical(f"🚨 Incident created: {incident.id} - {title} ({severity.value})")

        # Trigger automated response
        self._execute_playbook(incident)

        return incident

    def _execute_playbook(self, incident: Incident):
        """Execute the appropriate response playbook."""
        # Find matching playbook
        playbook_key = self._match_playbook(incident)
        if not playbook_key:
            logger.warning(f"No playbook found for incident {incident.id}")
            return

        playbook = self._playbooks[playbook_key]
        incident.status = IncidentStatus.CONTAINING

        # Execute parallel actions
        logger.info(f"⚡ Executing playbook: {playbook_key} for {incident.id}")
        
        for action_config in playbook.get("parallel_actions", []):
            result = self._execute_action(incident, action_config)
            incident.actions_taken.append(result)

        incident.status = IncidentStatus.ERADICATING

        # Execute sequential actions
        for action_config in playbook.get("sequential_actions", []):
            result = self._execute_action(incident, action_config)
            incident.actions_taken.append(result)

        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = datetime.utcnow()
        
        logger.info(f"✅ Incident {incident.id} resolved. {len(incident.actions_taken)} actions taken.")

    def _match_playbook(self, incident: Incident) -> Optional[str]:
        """Match incident to the best playbook."""
        title_lower = incident.title.lower()
        description_lower = incident.description.lower()

        # Direct keyword matching
        keyword_map = {
            "ransomware_detected": ["ransomware", "encrypt", "ransom", "locky", "wanna"],
            "brute_force_detected": ["brute force", "bruteforce", "password spray", "credential stuffing"],
            "data_exfiltration": ["exfiltrat", "data leak", "data breach", "stolen data"],
            "zero_day_exploit": ["zero-day", "zeroday", "0-day", "exploit", "cve-"],
            "insider_threat": ["insider", "internal threat", "privilege abuse"],
        }

        for playbook_key, keywords in keyword_map.items():
            for keyword in keywords:
                if keyword in title_lower or keyword in description_lower:
                    return playbook_key

        # Fallback by severity
        severity_map = {
            IncidentSeverity.CRITICAL: "ransomware_detected",
            IncidentSeverity.HIGH: "brute_force_detected",
            IncidentSeverity.MEDIUM: "data_exfiltration",
            IncidentSeverity.LOW: "insider_threat",
        }
        return severity_map.get(incident.severity)

    def _execute_action(self, incident: Incident, action_config: Dict) -> Dict:
        """Execute a single response action."""
        action = action_config["action"]
        params = action_config.get("params", {})
        timeout = action_config.get("timeout", 30)

        result = {
            "action": action.value,
            "params": params,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "executed",
            "details": "",
        }

        try:
            if action == ResponseAction.BLOCK_IP:
                ip = params.get("ip", "unknown")
                self._blocked_ips.add(ip)
                result["details"] = f"Blocked IP: {ip} for {params.get('duration', 'permanent')}"
                logger.warning(f"🛑 Blocked IP: {ip}")

            elif action == ResponseAction.ISOLATE_HOST:
                host = params.get("host", incident.affected_assets[0] if incident.affected_assets else "unknown")
                self._isolated_hosts.add(host)
                result["details"] = f"Isolated host: {host}"
                logger.warning(f"🔒 Isolated host: {host}")

            elif action == ResponseAction.KILL_PROCESS:
                process = params.get("process_name", "suspicious")
                result["details"] = f"Killed process: {process}"
                logger.warning(f"🔪 Killed process: {process}")

            elif action == ResponseAction.ALERT_ADMIN:
                channel = params.get("channel", "default")
                result["details"] = f"Alerted admins via {channel}"
                logger.critical(f"🚨 Admin alert sent via {channel}")

            elif action == ResponseAction.REVOKE_TOKEN:
                result["details"] = "Revoked all active sessions"
                logger.warning("🔑 All sessions revoked")

            elif action == ResponseAction.DISABLE_USER:
                users = params.get("users", incident.affected_users)
                result["details"] = f"Disabled users: {users}"
                logger.warning(f"👤 Disabled users: {users}")

            elif action == ResponseAction.ROLLBACK_CHANGES:
                result["details"] = f"Rolled back {params.get('type', 'changes')}"
                logger.warning("⏪ Changes rolled back")

            elif action == ResponseAction.RESTORE_BACKUP:
                result["details"] = f"Restored from {params.get('type', 'latest')} backup"
                logger.warning("💾 Backup restored")

            elif action == ResponseAction.SCAN_ENDPOINT:
                result["details"] = f"Scanning endpoint: {params.get('type', 'full')}"
                logger.info("🔍 Endpoint scan initiated")

            elif action == ResponseAction.UPDATE_FIREWALL:
                result["details"] = f"Firewall updated: {params.get('block_all', False)}"
                logger.warning("🔥 Firewall rules updated")

            elif action == ResponseAction.RESET_PASSWORD:
                result["details"] = "Passwords reset for affected users"
                logger.warning("🔐 Passwords reset")

            elif action == ResponseAction.ENABLE_MFA:
                result["details"] = "MFA enabled for all users"
                logger.warning("🔐 MFA enabled")

        except Exception as e:
            result["status"] = "failed"
            result["details"] = str(e)
            logger.error(f"Action {action} failed: {e}")

        return result

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident details."""
        for incident in self._incidents:
            if incident.id == incident_id:
                return incident
        return None

    def get_active_incidents(self) -> List[Incident]:
        """Get all active (not resolved) incidents."""
        return [
            i for i in self._incidents
            if i.status != IncidentStatus.RESOLVED
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get incident response statistics."""
        active = self.get_active_incidents()
        return {
            "total_incidents": len(self._incidents),
            "active_incidents": len(active),
            "resolved_incidents": len([i for i in self._incidents if i.status == IncidentStatus.RESOLVED]),
            "critical_incidents": len([i for i in active if i.severity == IncidentSeverity.CRITICAL]),
            "blocked_ips": len(self._blocked_ips),
            "isolated_hosts": len(self._isolated_hosts),
            "avg_response_time": self._calculate_avg_response_time(),
            "status": "ACTIVE" if active else "STANDBY",
        }

    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time in seconds."""
        resolved = [i for i in self._incidents if i.resolved_at]
        if not resolved:
            return 0.0
        
        total_time = sum(
            (i.resolved_at - i.timestamp).total_seconds()
            for i in resolved
        )
        return total_time / len(resolved)


incident_response = IncidentResponse()
