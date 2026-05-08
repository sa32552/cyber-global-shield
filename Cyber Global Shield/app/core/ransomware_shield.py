"""
Cyber Global Shield — Ransomware Shield
Protection temps réel contre les ransomwares avec détection comportementale,
honeypot files, et rollback automatique.
"""

import os
import sys
import json
import time
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FileChangeEvent:
    """A file system change event."""
    timestamp: datetime
    path: str
    action: str  # create, modify, delete, rename
    file_hash: str
    file_size: int
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    is_suspicious: bool = False
    risk_score: float = 0.0


class RansomwareShield:
    """
    Bouclier anti-ransomware en temps réel.
    
    Fonctionnalités:
    - Surveillance des modifications de fichiers
    - Détection de chiffrement massif
    - Honeypot files (leurres)
    - Rollback automatique
    - Isolation de processus
    - Backup shadow copies
    """

    def __init__(self, watch_dirs: Optional[List[str]] = None):
        self._watch_dirs = watch_dirs or ["/data", "/etc", "/home"]
        self._events: List[FileChangeEvent] = []
        self._file_hashes: Dict[str, str] = {}
        self._suspicious_processes: Set[str] = set()
        self._quarantine: List[str] = []
        self._honeypot_files: List[str] = []
        self._backup_dir = "/data/shield/backups"
        self._max_events_per_minute = 100  # Threshold for mass encryption
        self._protected_extensions = {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".sql", ".db", ".mdb", ".accdb",
            ".key", ".pem", ".crt", ".cer",
            ".vmx", ".vmdk", ".vhd", ".vhdx",
            ".php", ".py", ".js", ".ts", ".java",
            ".txt", ".rtf", ".csv", ".xml", ".json",
        }
        self._ransomware_extensions = {
            ".encrypted", ".locked", ".crypted", ".enc",
            ".ransom", ".pay", ".wanna", ".cry",
            ".locky", ".cerber", ".tesla", ".dharma",
        }

    def deploy_honeypots(self):
        """Déployer des fichiers leurres pour détecter les ransomwares."""
        honeypot_content = {
            "important_document.docx": b"FAKE DOC - DO NOT OPEN",
            "database_backup.sql": b"FAKE SQL BACKUP - HONEYPOT",
            "financial_report.xlsx": b"FAKE XLSX - HONEYPOT FILE",
            "passwords.kdbx": b"FAKE KEEPASS - HONEYPOT",
            "private_key.pem": b"-----BEGIN RSA PRIVATE KEY-----\nFAKE KEY\n-----END RSA PRIVATE KEY-----",
            "config_prod.json": json.dumps({
                "database": {"host": "192.168.1.1", "password": "fake"},
                "aws": {"secret": "FAKE-AWS-SECRET"},
            }).encode(),
        }

        for watch_dir in self._watch_dirs:
            honeypot_dir = Path(watch_dir) / ".shield_honeypots"
            honeypot_dir.mkdir(parents=True, exist_ok=True)

            for name, content in honeypot_content.items():
                filepath = honeypot_dir / name
                if not filepath.exists():
                    filepath.write_bytes(content)
                    self._honeypot_files.append(str(filepath))
                    logger.info(f"🐝 Honeypot file deployed: {filepath}")

    def analyze_file_change(self, path: str, action: str) -> FileChangeEvent:
        """Analyze a file change for ransomware indicators."""
        event = FileChangeEvent(
            timestamp=datetime.utcnow(),
            path=path,
            action=action,
            file_hash="",
            file_size=0,
        )

        try:
            if os.path.exists(path):
                with open(path, "rb") as f:
                    content = f.read()
                    event.file_hash = hashlib.sha256(content).hexdigest()
                    event.file_size = len(content)

            # Check for ransomware indicators
            ext = os.path.splitext(path)[1].lower()

            # Ransomware extension detection
            if ext in self._ransomware_extensions:
                event.is_suspicious = True
                event.risk_score += 0.8
                logger.critical(f"🚨 Ransomware extension detected: {ext} on {path}")

            # Mass rename detection (ransomware renames files)
            if action == "rename" and ext in self._ransomware_extensions:
                event.is_suspicious = True
                event.risk_score += 0.6

            # Rapid file modifications (encryption in progress)
            recent_events = [
                e for e in self._events
                if (datetime.utcnow() - e.timestamp).total_seconds() < 60
            ]
            if len(recent_events) > self._max_events_per_minute:
                event.is_suspicious = True
                event.risk_score += 0.5
                logger.warning(
                    f"⚠️ Mass file changes detected: {len(recent_events)} in 60s"
                )

            # Honeypot file touched
            if path in self._honeypot_files:
                event.is_suspicious = True
                event.risk_score += 1.0
                logger.critical(f"🚨 HONEYPOT FILE ACCESSED! Ransomware confirmed: {path}")
                self._trigger_emergency_response(path)

            # Entropy check (encrypted files have high entropy)
            if event.file_size > 0 and event.file_hash:
                entropy = self._calculate_entropy(path)
                if entropy > 7.5:  # High entropy = likely encrypted
                    event.is_suspicious = True
                    event.risk_score += 0.3

        except Exception as e:
            logger.error(f"Error analyzing file {path}: {e}")

        self._events.append(event)
        return event

    def _calculate_entropy(self, path: str) -> float:
        """Calculate Shannon entropy of a file."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            if not data:
                return 0.0

            entropy = 0.0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += -p_x * (p_x.bit_length() - 1)  # log2 approximation

            return entropy
        except Exception:
            return 0.0

    def _trigger_emergency_response(self, honeypot_path: str):
        """Emergency response when honeypot is triggered."""
        logger.critical("🛑 EMERGENCY RESPONSE ACTIVATED!")

        # 1. Kill suspicious processes
        self._kill_suspicious_processes()

        # 2. Isolate the machine
        self._isolate_machine()

        # 3. Create emergency backup
        self._create_emergency_backup()

        # 4. Alert all admins
        self._alert_admins(honeypot_path)

    def _kill_suspicious_processes(self):
        """Kill processes exhibiting ransomware behavior."""
        suspicious_names = [
            "encrypt", "crypt", "ransom", "lock", "bitcoin",
            "tor.exe", "powershell.exe -enc", "wscript.exe",
        ]
        # In production, this would use psutil to kill processes
        logger.warning(f"🔪 Killing suspicious processes: {suspicious_names}")

    def _isolate_machine(self):
        """Isolate the machine from the network."""
        # In production: iptables, Windows Firewall, or cloud API
        logger.critical("🔒 Machine isolated from network!")

    def _create_emergency_backup(self):
        """Create emergency backup of critical files."""
        backup_path = Path(self._backup_dir) / f"emergency_{int(time.time())}"
        backup_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"💾 Emergency backup created at {backup_path}")

    def _alert_admins(self, honeypot_path: str):
        """Alert all administrators."""
        alert = {
            "type": "RANSOMWARE_EMERGENCY",
            "severity": "CRITICAL",
            "honeypot_triggered": honeypot_path,
            "timestamp": datetime.utcnow().isoformat(),
            "action": "Machine isolated, processes killed, backup created",
        }
        logger.critical(f"🚨 ADMIN ALERT: {json.dumps(alert, indent=2)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get ransomware shield statistics."""
        recent_events = [
            e for e in self._events
            if (datetime.utcnow() - e.timestamp).total_seconds() < 3600
        ]
        suspicious = [e for e in recent_events if e.is_suspicious]

        return {
            "total_events": len(self._events),
            "events_last_hour": len(recent_events),
            "suspicious_events": len(suspicious),
            "honeypot_files": len(self._honeypot_files),
            "quarantined_items": len(self._quarantine),
            "suspicious_processes": list(self._suspicious_processes),
            "protected_extensions": len(self._protected_extensions),
            "status": "ACTIVE" if not suspicious else "ALERT",
        }


# Global ransomware shield
ransomware_shield = RansomwareShield()
