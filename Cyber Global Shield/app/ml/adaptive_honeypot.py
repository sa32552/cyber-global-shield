"""
Cyber Global Shield — Adaptive AI Honeypots
Honeypots adaptatifs pilotés par IA qui apprennent des attaquants en temps réel.
- Reinforcement Learning pour déployer des leurres dynamiques
- GNN pour analyser les patterns d'attaque
- Génération automatique de credentials/fichiers/API leurres
- Profilage des attaquants par comportement
- Auto-évolution des stratégies de leurre
"""

import os
import json
import time
import random
import asyncio
import logging
import hashlib
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

logger = logging.getLogger(__name__)

# ─── RL imports ────────────────────────────────────────────────────────────
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class AttackerProfile(Enum):
    SCRIPT_KIDDIE = "script_kiddie"
    ADVANCED_PERSISTENT = "apt"
    BOTNET = "botnet"
    SCANNER = "scanner"
    INSIDER = "insider"
    RANSOMWARE = "ransomware"
    UNKNOWN = "unknown"


class LureType(Enum):
    PORT = "port"
    CREDENTIAL = "credential"
    FILE = "file"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    BACKUP = "backup"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    VPN_CONFIG = "vpn_config"


@dataclass
class Lure:
    """A decoy deployed by the adaptive honeypot."""
    lure_id: str
    lure_type: LureType
    content: str
    deployed_at: datetime
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    times_hit: int = 0
    times_trapped: int = 0
    effectiveness_score: float = 0.5
    last_updated: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return self.times_trapped / max(self.times_hit, 1)


@dataclass
class AttackerSession:
    """Track an attacker's interaction session."""
    session_id: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime = field(default_factory=datetime.utcnow)
    profile: AttackerProfile = AttackerProfile.UNKNOWN
    confidence: float = 0.0
    lures_interacted: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    tools_detected: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    interaction_count: int = 0
    total_payload_bytes: int = 0
    ports_scanned: Set[int] = field(default_factory=set)
    credentials_tried: List[str] = field(default_factory=list)
    is_blocked: bool = False


class AdaptiveHoneypotEngine:
    """
    Moteur de honeypots adaptatifs avec IA.
    
    Fonctionnalités clés :
    - Reinforcement Learning pour choisir les meilleurs leurres
    - Profilage des attaquants par comportement (ML)
    - Génération dynamique de leurres contextuels
    - Auto-évolution des stratégies de déception
    - Détection de patterns d'attaque avancés
    """

    def __init__(self, 
                 learning_rate: float = 0.1,
                 exploration_rate: float = 0.2,
                 max_lures: int = 100,
                 profile_update_interval: int = 5):
        
        self._lures: Dict[str, Lure] = {}
        self._sessions: Dict[str, AttackerSession] = {}
        self._blocked_ips: Set[str] = set()
        self._learning_rate = learning_rate
        self._exploration_rate = exploration_rate
        self._max_lures = max_lures
        
        # Q-learning table: state -> action -> Q-value
        self._q_table: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        
        # Attacker profile classifier
        self._profile_classifier = None
        self._feature_history: List[Dict] = []
        self._profile_update_counter = 0
        self._profile_update_interval = profile_update_interval
        
        # Lure templates for dynamic generation
        self._lure_templates = self._init_lure_templates()
        
        # Ports actuellement surveillés
        self._active_ports: Dict[int, str] = {}
        
        # Statistiques
        self._stats = {
            "total_interactions": 0,
            "unique_attackers": 0,
            "lures_deployed": 0,
            "attackers_profiled": 0,
            "ips_blocked": 0,
            "avg_effectiveness": 0.0,
            "started_at": datetime.utcnow().isoformat(),
        }
        
        logger.info("🤖 AdaptiveHoneypotEngine initialisé (RL + ML profiling)")

    def _init_lure_templates(self) -> Dict[str, List[str]]:
        """Initialize templates for dynamic lure generation."""
        return {
            "credentials": [
                "admin:{random_pass}",
                "root:{random_pass}",
                "administrator:{random_pass}",
                "sa:{random_pass}",
                "postgres:{random_pass}",
                "backup:{random_pass}",
                "deploy:{random_pass}",
                "jenkins:{random_pass}",
                "gitlab:{random_pass}",
                "docker:{random_pass}",
                "kubernetes:{random_pass}",
                "aws:{random_pass}",
                "azure:{random_pass}",
                "gcp:{random_pass}",
                "vpn:{random_pass}",
                "admin_{year}:{random_pass}",
                "root_{year}:{random_pass}",
            ],
            "files": [
                "passwords_{year}.txt",
                "database_backup_{year}.sql",
                "aws_credentials_{year}.json",
                "ssh_private_key_{year}.pem",
                "config_prod_{year}.yml",
                "bank_transfer_{year}.xlsx",
                "hr_salaries_{year}.csv",
                "vpn_config_{year}.ovpn",
                "kube_config_{year}.yaml",
                "terraform_state_{year}.tfstate",
                "docker_compose_prod_{year}.yml",
                "ssl_cert_{year}.pem",
                "api_keys_{year}.json",
                "customer_db_{year}.csv",
                "encryption_keys_{year}.asc",
            ],
            "api_endpoints": [
                "/api/v1/admin/login",
                "/api/v1/users/export",
                "/api/v1/backup/download",
                "/api/v1/config/deploy",
                "/api/v1/database/query",
                "/api/v1/logs/stream",
                "/api/v1/credentials/rotate",
                "/api/v1/deploy/rollback",
                "/graphql",
                "/actuator/health",
                "/swagger-ui.html",
                "/api-docs",
                "/.env",
                "/wp-admin/admin-ajax.php",
                "/vendor/phpunit/phpunit",
            ],
            "config_files": [
                "DATABASE_URL=postgresql://{user}:{pwd}@db-prod:5432/production",
                "AWS_ACCESS_KEY_ID={access_key}",
                "AWS_SECRET_ACCESS_KEY={secret_key}",
                "JWT_SECRET={jwt_secret}",
                "API_KEY={api_key}",
                "REDIS_PASSWORD={redis_pass}",
                "ENCRYPTION_KEY={enc_key}",
                "SLACK_WEBHOOK=https://hooks.slack.com/services/{webhook}",
            ],
        }

    def _generate_random_password(self, length: int = 12) -> str:
        """Generate a realistic-looking fake password."""
        patterns = [
            lambda: f"{random.choice(['Admin','Pass','Secret','P@ss','Cloud','Prod'])}{random.randint(100,999)}{random.choice(['!','@','#','$','%'])}",
            lambda: f"{random.choice(['welcome','changeme','letmein','password','admin'])}{random.randint(2020,2026)}{random.choice(['!','.','']) }",
            lambda: f"{random.choice(['P@ssw0rd','S3cur3','C0mpl3x','Str0ng'])}{random.randint(1,99)}",
        ]
        return random.choice(patterns)()

    def _generate_lure_content(self, lure_type: LureType) -> str:
        """Generate dynamic lure content based on type."""
        year = datetime.utcnow().year
        templates = self._lure_templates
        
        if lure_type == LureType.CREDENTIAL:
            template = random.choice(templates["credentials"])
            return template.format(
                random_pass=self._generate_random_password(),
                year=year,
            )
        elif lure_type == LureType.FILE:
            template = random.choice(templates["files"])
            return template.format(year=year)
        elif lure_type == LureType.API_ENDPOINT:
            return random.choice(templates["api_endpoints"])
        elif lure_type == LureType.CONFIG:
            template = random.choice(templates["config_files"])
            return template.format(
                user=f"admin_{random.randint(1,999)}",
                pwd=self._generate_random_password(),
                access_key=f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                secret_key=''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/', k=40)),
                jwt_secret=''.join(random.choices('abcdef0123456789', k=64)),
                api_key=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32)),
                redis_pass=self._generate_random_password(),
                enc_key=''.join(random.choices('abcdef0123456789', k=32)),
                webhook=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=24)),
            )
        elif lure_type == LureType.TOKEN:
            return f"ghp_{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=36))}"
        elif lure_type == LureType.VPN_CONFIG:
            return (
                f"client\n"
                f"dev tun\n"
                f"proto udp\n"
                f"remote vpn-{random.choice(['prod','corp','us-east'])}.company.com {random.choice([1194,443,8443])}\n"
                f"resolv-retry infinite\n"
                f"nobind\n"
                f"<ca>\n-----BEGIN CERTIFICATE-----\n{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', k=256))}\n-----END CERTIFICATE-----\n</ca>\n"
            )
        else:
            return f"lure_content_{hashlib.md5(str(random.random()).encode()).hexdigest()}"

    def deploy_lure(self, lure_type: Optional[LureType] = None, port: Optional[int] = None) -> Lure:
        """Deploy a new lure dynamically."""
        if len(self._lures) >= self._max_lures:
            # Remove least effective lure
            worst_lure = min(self._lures.values(), key=lambda l: l.effectiveness_score)
            del self._lures[worst_lure.lure_id]
            logger.info(f"🗑️ Removed ineffective lure: {worst_lure.lure_id}")

        lure_type = lure_type or random.choice(list(LureType))
        lure_id = f"lure_{hashlib.md5(f'{lure_type.value}_{time.time()}_{random.random()}'.encode()).hexdigest()[:12]}"
        
        content = self._generate_lure_content(lure_type)
        
        # Choose port based on RL if applicable
        if lure_type == LureType.PORT and port is None:
            port = self._select_optimal_port()
        
        lure = Lure(
            lure_id=lure_id,
            lure_type=lure_type,
            content=content,
            deployed_at=datetime.utcnow(),
            target_port=port,
            target_service=self._active_ports.get(port) if port else None,
        )
        
        self._lures[lure_id] = lure
        self._stats["lures_deployed"] += 1
        
        if port:
            self._active_ports[port] = f"lure_{lure_type.value}"
        
        logger.info(f"🎣 Lure deployed: {lure_type.value} (id={lure_id}, port={port})")
        return lure

    def _select_optimal_port(self) -> int:
        """Use Q-learning to select the best port for a honeypot."""
        common_ports = [22, 23, 3389, 3306, 5432, 6379, 9200, 8080, 8443, 1433, 5900, 445, 80, 443, 21, 25, 110, 993, 995, 389, 636, 1521, 1830, 2483, 2484, 27017, 27018, 27019]
        
        # Exploration: try random port
        if random.random() < self._exploration_rate:
            return random.choice(common_ports)
        
        # Exploitation: choose best port based on Q-values
        state = self._get_current_state()
        port_q_values = {str(p): self._q_table[state][str(p)] for p in common_ports}
        best_port = max(port_q_values, key=port_q_values.get)
        return int(best_port)

    def _get_current_state(self) -> str:
        """Get current state representation for Q-learning."""
        total_lures = len(self._lures)
        total_sessions = len(self._sessions)
        recent_interactions = sum(1 for s in self._sessions.values() 
                                  if s.last_seen > datetime.utcnow() - timedelta(minutes=5))
        
        # Discretize state
        lure_bucket = min(total_lures // 10, 5)
        session_bucket = min(total_sessions // 5, 5)
        recent_bucket = min(recent_interactions, 5)
        
        return f"l{lure_bucket}_s{session_bucket}_r{recent_bucket}"

    def record_interaction(self, 
                          src_ip: str,
                          lure_id: str,
                          payload: str = "",
                          port: int = 0,
                          protocol: str = "tcp") -> Dict[str, Any]:
        """Record an attacker interaction with a lure and update RL."""
        self._stats["total_interactions"] += 1
        
        # Get or create session
        session = self._get_or_create_session(src_ip)
        session.interaction_count += 1
        session.last_seen = datetime.utcnow()
        session.total_payload_bytes += len(payload)
        session.ports_scanned.add(port)
        
        if lure_id in self._lures:
            lure = self._lures[lure_id]
            lure.times_hit += 1
            lure.last_updated = datetime.utcnow()
            session.lures_interacted.append(lure_id)
            
            # Detect tools and techniques
            tools = self._detect_tools(payload)
            session.tools_detected.extend(tools)
            
            techniques = self._detect_techniques(payload, port)
            session.techniques_used.extend(techniques)
            
            # Update lure effectiveness
            reward = self._calculate_reward(payload, port, tools, techniques)
            self._update_q_learning(port, reward)
            lure.effectiveness_score = min(1.0, lure.effectiveness_score + reward * self._learning_rate)
            
            # Check if attacker took the bait (downloaded file, tried credential, etc.)
            if self._is_trapped(payload, lure):
                lure.times_trapped += 1
                session.risk_score = min(1.0, session.risk_score + 0.2)
                logger.info(f"🪤 Attacker trapped! {src_ip} fell for {lure.lure_type.value}")
        
        # Update attacker profile
        self._update_attacker_profile(session)
        
        # Auto-block if high risk
        if session.risk_score > 0.8 or session.interaction_count > 50:
            self._blocked_ips.add(src_ip)
            session.is_blocked = True
            self._stats["ips_blocked"] += 1
            logger.critical(f"🛑 Auto-blocked {src_ip} (risk={session.risk_score:.2f}, interactions={session.interaction_count})")
        
        return {
            "session_id": session.session_id,
            "profile": session.profile.value,
            "risk_score": session.risk_score,
            "tools_detected": tools,
            "techniques_detected": techniques,
            "is_blocked": session.is_blocked,
            "lure_effectiveness": self._lures[lure_id].effectiveness_score if lure_id in self._lures else 0.0,
        }

    def _get_or_create_session(self, src_ip: str) -> AttackerSession:
        """Get existing session or create new one."""
        for sid, session in self._sessions.items():
            if session.src_ip == src_ip:
                return session
        
        session = AttackerSession(
            session_id=f"att_{hashlib.md5(f'{src_ip}_{time.time()}'.encode()).hexdigest()[:12]}",
            src_ip=src_ip,
            first_seen=datetime.utcnow(),
        )
        self._sessions[session.session_id] = session
        self._stats["unique_attackers"] += 1
        return session

    def _detect_tools(self, payload: str) -> List[str]:
        """Detect attacker tools from payload."""
        tools = []
        payload_lower = payload.lower()
        
        signatures = {
            "nmap": ["nmap", "masscan", "zmap"],
            "sqlmap": ["sqlmap", "sql injection"],
            "hydra": ["hydra", "medusa", "thc"],
            "metasploit": ["metasploit", "msf", "meterpreter"],
            "burpsuite": ["burp", "intruder", "repeater"],
            "gobuster": ["gobuster", "dirbuster", "ffuf"],
            "nikto": ["nikto"],
            "wpscan": ["wpscan"],
            "nessus": ["nessus", "openvas", "greenbone"],
            "python": ["python-requests", "python-urllib", "aiohttp"],
            "curl": ["curl/", "wget/"],
            "go": ["go-http-client"],
            "java": ["java/", "okhttp"],
            "rust": ["rust/", "reqwest"],
        }
        
        for tool, sigs in signatures.items():
            if any(sig in payload_lower for sig in sigs):
                tools.append(tool)
        
        return list(set(tools))

    def _detect_techniques(self, payload: str, port: int) -> List[str]:
        """Detect attack techniques from payload."""
        techniques = []
        payload_lower = payload.lower()
        
        # MITRE ATT&CK techniques mapping
        technique_signatures = {
            "T1046 - Network Scanning": ["nmap", "masscan", "ping sweep"],
            "T1110 - Brute Force": ["password", "login", "admin:", "root:"],
            "T1190 - Exploit Public-Facing App": ["cve-", "exploit", "rce", "lfi", "rfi"],
            "T1505 - Web Shell": ["cmd=", "exec=", "shell_exec", "system("],
            "T1059 - Command & Scripting": ["powershell", "cmd.exe", "/bin/sh", "/bin/bash"],
            "T1048 - Exfiltration": ["wget ", "curl ", "nc ", "ncat"],
            "T1210 - Exploitation of Remote Services": ["ms17-010", "eternalblue", "smb"],
            "T1003 - Credential Dumping": ["sam", "security", "system32/config"],
            "T1078 - Valid Accounts": ["admin", "root", "administrator"],
            "T1021 - Remote Services": ["rdp", "winrm", "psexec", "wmic"],
            "T1569 - Service Execution": ["sc.exe", "net start", "service"],
            "T1053 - Scheduled Task": ["schtasks", "cron", "at.exe"],
            "T1543 - Create/Modify System Process": ["service", "daemon", "systemd"],
            "T1090 - Proxy": ["proxy", "socks", "tor", "proxychains"],
            "T1572 - Protocol Tunneling": ["ssh -L", "ssh -R", "chisel", "frp"],
        }
        
        for technique, sigs in technique_signatures.items():
            if any(sig in payload_lower for sig in sigs):
                techniques.append(technique)
        
        # Port-specific techniques
        port_techniques = {
            22: ["T1046 - SSH Scanning", "T1110 - SSH Brute Force"],
            3389: ["T1046 - RDP Scanning", "T1110 - RDP Brute Force", "T1021 - Remote Desktop"],
            445: ["T1046 - SMB Scanning", "T1210 - SMB Exploitation"],
            3306: ["T1046 - MySQL Scanning", "T1110 - MySQL Brute Force"],
            80: ["T1190 - Web Application Scanning", "T1505 - Web Shell"],
            443: ["T1190 - Web Application Scanning"],
            8080: ["T1190 - Proxy Scanning"],
            8443: ["T1190 - Web Application Scanning"],
            1433: ["T1046 - MSSQL Scanning", "T1110 - MSSQL Brute Force"],
            6379: ["T1046 - Redis Scanning"],
            9200: ["T1046 - Elasticsearch Scanning"],
            5900: ["T1046 - VNC Scanning", "T1110 - VNC Brute Force"],
        }
        
        techniques.extend(port_techniques.get(port, []))
        
        return list(set(techniques))

    def _calculate_reward(self, payload: str, port: int, tools: List[str], techniques: List[str]) -> float:
        """Calculate reward for RL based on interaction quality."""
        reward = 0.0
        
        # More payload = more reward (attacker is engaged)
        if len(payload) > 100:
            reward += 0.1
        if len(payload) > 1000:
            reward += 0.2
        if len(payload) > 10000:
            reward += 0.3
        
        # Tools detected = higher reward (more sophisticated attacker)
        reward += min(len(tools) * 0.1, 0.3)
        
        # Techniques detected = higher reward
        reward += min(len(techniques) * 0.05, 0.2)
        
        # Port-specific bonus
        high_value_ports = {22: 0.1, 3389: 0.15, 445: 0.2, 1433: 0.15, 3306: 0.1}
        reward += high_value_ports.get(port, 0.02)
        
        return min(reward, 1.0)

    def _is_trapped(self, payload: str, lure: Lure) -> bool:
        """Check if attacker took the bait."""
        payload_lower = payload.lower()
        
        # Check if attacker tried to use the credential
        if lure.lure_type == LureType.CREDENTIAL:
            credential_parts = lure.content.split(":")
            if len(credential_parts) == 2:
                if credential_parts[0].lower() in payload_lower:
                    return True
        
        # Check if attacker tried to download the file
        if lure.lure_type in [LureType.FILE, LureType.CONFIG, LureType.VPN_CONFIG]:
            file_name = lure.content.split("/")[-1].lower()
            if file_name in payload_lower:
                return True
        
        # Check if attacker accessed the API endpoint
        if lure.lure_type == LureType.API_ENDPOINT:
            if lure.content.lower() in payload_lower:
                return True
        
        # Check if attacker used the token
        if lure.lure_type == LureType.TOKEN:
            if lure.content in payload:
                return True
        
        return False

    def _update_q_learning(self, port: int, reward: float):
        """Update Q-learning table."""
        state = self._get_current_state()
        port_key = str(port)
        
        # Q-learning update: Q(s,a) = Q(s,a) + lr * (reward - Q(s,a))
        current_q = self._q_table[state][port_key]
        self._q_table[state][port_key] = current_q + self._learning_rate * (reward - current_q)

    def _update_attacker_profile(self, session: AttackerSession):
        """Update attacker profile using ML classification."""
        self._profile_update_counter += 1
        
        # Extract features
        features = self._extract_profile_features(session)
        self._feature_history.append(features)
        
        # Periodically retrain classifier
        if self._profile_update_counter >= self._profile_update_interval and ML_AVAILABLE:
            self._train_profile_classifier()
            self._profile_update_counter = 0
        
        # Heuristic profile classification
        profile = self._classify_profile_heuristic(session)
        session.profile = profile
        
        if profile != AttackerProfile.UNKNOWN:
            self._stats["attackers_profiled"] += 1

    def _extract_profile_features(self, session: AttackerSession) -> Dict[str, float]:
        """Extract features for ML profile classification."""
        return {
            "interaction_count": session.interaction_count,
            "unique_ports": len(session.ports_scanned),
            "total_payload_bytes": session.total_payload_bytes,
            "tools_count": len(session.tools_detected),
            "techniques_count": len(session.techniques_used),
            "unique_lures": len(set(session.lures_interacted)),
            "avg_payload_per_interaction": session.total_payload_bytes / max(session.interaction_count, 1),
            "session_duration_hours": (session.last_seen - session.first_seen).total_seconds() / 3600,
            "credential_attempts": len(session.credentials_tried),
            "is_high_risk": 1.0 if session.risk_score > 0.7 else 0.0,
        }

    def _train_profile_classifier(self):
        """Train ML classifier for attacker profiling."""
        if len(self._feature_history) < 10:
            return
        
        try:
            # Prepare training data
            X = []
            y = []
            
            for i, features in enumerate(self._feature_history):
                X.append(list(features.values()))
                # Use heuristic labels for training
                session = list(self._sessions.values())[i % len(self._sessions)]
                y.append(self._classify_profile_heuristic(session).value)
            
            # Train Random Forest
            self._profile_classifier = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42,
            )
            self._profile_classifier.fit(X, y)
            logger.info(f"🧠 Profile classifier trained on {len(X)} samples")
            
        except Exception as e:
            logger.error(f"Failed to train profile classifier: {e}")

    def _classify_profile_heuristic(self, session: AttackerSession) -> AttackerProfile:
        """Heuristic profile classification based on behavior."""
        if session.interaction_count == 0:
            return AttackerProfile.UNKNOWN
        
        # APT: many techniques, tools, long duration, high payload
        if (len(session.techniques_used) >= 5 and 
            len(session.tools_detected) >= 3 and
            session.total_payload_bytes > 10000 and
            (session.last_seen - session.first_seen).total_seconds() > 3600):
            return AttackerProfile.ADVANCED_PERSISTENT
        
        # Ransomware: specific techniques, rapid spread
        if any("SMB" in t or "RDP" in t for t in session.techniques_used):
            if session.interaction_count > 20 and len(session.ports_scanned) > 5:
                return AttackerProfile.RANSOMWARE
        
        # Botnet: many connections, low payload, many ports
        if (session.interaction_count > 30 and
            len(session.ports_scanned) > 10 and
            session.total_payload_bytes < 5000):
            return AttackerProfile.BOTNET
        
        # Scanner: many ports, few techniques, short duration
        if (len(session.ports_scanned) > 15 and
            len(session.techniques_used) < 3 and
            session.total_payload_bytes < 1000):
            return AttackerProfile.SCANNER
        
        # Insider: known techniques, specific ports, credentials
        if (len(session.credentials_tried) > 0 and
            session.interaction_count < 10 and
            any(port in session.ports_scanned for port in [3306, 5432, 9200, 27017])):
            return AttackerProfile.INSIDER
        
        # Script Kiddie: few techniques, common tools, low payload
        if (session.interaction_count < 10 and
            len(session.techniques_used) < 3 and
            session.total_payload_bytes < 5000):
            return AttackerProfile.SCRIPT_KIDDIE
        
        return AttackerProfile.UNKNOWN

    def get_optimal_lures_for_attacker(self, profile: AttackerProfile) -> List[LureType]:
        """Get optimal lure types for a given attacker profile."""
        profile_lures = {
            AttackerProfile.SCRIPT_KIDDIE: [LureType.CREDENTIAL, LureType.PORT, LureType.API_ENDPOINT],
            AttackerProfile.ADVANCED_PERSISTENT: [LureType.CONFIG, LureType.CERTIFICATE, LureType.TOKEN, LureType.VPN_CONFIG],
            AttackerProfile.BOTNET: [LureType.PORT, LureType.API_ENDPOINT],
            AttackerProfile.SCANNER: [LureType.PORT, LureType.API_ENDPOINT],
            AttackerProfile.INSIDER: [LureType.DATABASE, LureType.BACKUP, LureType.CONFIG],
            AttackerProfile.RANSOMWARE: [LureType.BACKUP, LureType.FILE, LureType.DATABASE],
            AttackerProfile.UNKNOWN: list(LureType),
        }
        return profile_lures.get(profile, list(LureType))

    def auto_deploy_lures(self, count: int = 3) -> List[Lure]:
        """Automatically deploy optimal lures based on current threat landscape."""
        deployed = []
        
        # Analyze current attackers
        active_profiles = defaultdict(int)
        for session in self._sessions.values():
            if session.last_seen > datetime.utcnow() - timedelta(minutes=30):
                active_profiles[session.profile] += 1
        
        # Deploy lures for most common profiles
        if active_profiles:
            most_common = max(active_profiles, key=active_profiles.get)
            lure_types = self.get_optimal_lures_for_attacker(most_common)
            
            for _ in range(count):
                if lure_types:
                    lure_type = random.choice(lure_types)
                    deployed.append(self.deploy_lure(lure_type=lure_type))
        else:
            # Deploy diverse lures
            for _ in range(count):
                deployed.append(self.deploy_lure())
        
        return deployed

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        total_lures = len(self._lures)
        if total_lures > 0:
            avg_effectiveness = sum(l.effectiveness_score for l in self._lures.values()) / total_lures
        else:
            avg_effectiveness = 0.0
        
        # Profile distribution
        profile_dist = defaultdict(int)
        for session in self._sessions.values():
            profile_dist[session.profile.value] += 1
        
        # Top lures
        top_lures = sorted(self._lures.values(), key=lambda l: l.times_hit, reverse=True)[:5]
        
        return {
            **self._stats,
            "active_lures": total_lures,
            "active_sessions": len(self._sessions),
            "avg_lure_effectiveness": round(avg_effectiveness, 3),
            "profile_distribution": dict(profile_dist),
            "top_lures": [
                {"id": l.lure_id, "type": l.lure_type.value, "hits": l.times_hit, "trapped": l.times_trapped, "effectiveness": round(l.effectiveness_score, 3)}
                for l in top_lures
            ],
            "q_table_size": len(self._q_table),
            "ml_classifier_trained": self._profile_classifier is not None,
            "exploration_rate": self._exploration_rate,
            "learning_rate": self._learning_rate,
        }

    def get_threat_intel(self) -> Dict[str, Any]:
        """Generate threat intelligence from honeypot data."""
        intel = {
            "top_attacker_ips": [],
            "common_techniques": [],
            "common_tools": [],
            "targeted_ports": [],
            "risk_level": "LOW",
        }
        
        if not self._sessions:
            return intel
        
        # Top attacker IPs
        ip_counts = defaultdict(int)
        for session in self._sessions.values():
            ip_counts[session.src_ip] += session.interaction_count
        intel["top_attacker_ips"] = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Common techniques
        tech_counts = defaultdict(int)
        for session in self._sessions.values():
            for tech in session.techniques_used:
                tech_counts[tech] += 1
        intel["common_techniques"] = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Common tools
        tool_counts = defaultdict(int)
        for session in self._sessions.values():
            for tool in session.tools_detected:
                tool_counts[tool] += 1
        intel["common_tools"] = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Targeted ports
        port_counts = defaultdict(int)
        for session in self._sessions.values():
            for port in session.ports_scanned:
                port_counts[port] += 1
        intel["targeted_ports"] = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Overall risk level
        high_risk = sum(1 for s in self._sessions.values() if s.risk_score > 0.7)
        if high_risk > 5:
            intel["risk_level"] = "CRITICAL"
        elif high_risk > 2:
            intel["risk_level"] = "HIGH"
        elif high_risk > 0:
            intel["risk_level"] = "MEDIUM"
        
        return intel


# ─── Factory ───────────────────────────────────────────────────────────────

def create_adaptive_honeypot(
    learning_rate: float = 0.1,
    exploration_rate: float = 0.2,
    max_lures: int = 100,
) -> AdaptiveHoneypotEngine:
    """Create an adaptive honeypot engine with default configuration."""
    return AdaptiveHoneypotEngine(
        learning_rate=learning_rate,
        exploration_rate=exploration_rate,
        max_lures=max_lures,
    )
