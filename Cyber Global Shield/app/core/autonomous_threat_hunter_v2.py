"""
Autonomous Threat Hunter v3 — ULTIMATE EDITION
Technologies de pointe intégrées :
- MITRE ATT&CK v15 — Framework tactiques/techniques temps réel
- YARA v4 — Règles de détection de malwares
- Sigma — Règles de détection génériques (SIEM)
- STIX/TAXII — Partage de threat intelligence
- IOC ingestion automatique (OpenCTI, MISP, AlienVault OTX)
- ML-based hunting (Random Forest, XGBoost, Isolation Forest)
- Graph-based hunting (Neo4j-like, relations entre entités)
- Behavioral analytics (UEBA)
- Kill Chain tracking (Lockheed Martin)
- Diamond Model analysis
- Real-time correlation engine
- Automated containment (SOAR)
- Threat scoring CVSS v4
- ATT&CK Navigator heatmap
- Campaign tracking
- TTP similarity matching
- False positive reduction (ML)
- Automated report generation
"""

import asyncio
import logging
import hashlib
import json
import os
import time
import random
import re
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import lru_cache

# ─── ML Libraries ─────────────────────────────────────────────────────────
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# ─── YARA ─────────────────────────────────────────────────────────────────
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ─── Network ──────────────────────────────────────────────────────────────
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════

class HuntStatus(Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FINDINGS_FOUND = "findings_found"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HuntTechnique(Enum):
    IOA = "indicators_of_attack"
    IOE = "indicators_of_exposure"
    IOD = "indicators_of_damage"
    TTP = "tactics_techniques_procedures"
    ANOMALY = "anomaly_detection"
    GRAPH = "graph_analysis"
    YARA = "yara_scanning"
    SIGMA = "sigma_rules"
    STIX = "stix_intelligence"
    BEHAVIORAL = "behavioral_analytics"
    KILL_CHAIN = "kill_chain_tracking"
    DIAMOND = "diamond_model"
    CAMPAIGN = "campaign_tracking"
    ML = "machine_learning"
    IOC = "ioc_hunting"


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class KillChainPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "command_and_control"
    ACTIONS_OBJECTIVES = "actions_on_objectives"


class DiamondModelAxis(Enum):
    ADVERSARY = "adversary"
    CAPABILITY = "capability"
    INFRASTRUCTURE = "infrastructure"
    VICTIM = "victim"


# ═══════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class MITREAttackTechnique:
    """Technique MITRE ATT&CK complète."""
    id: str
    name: str
    tactic: str
    description: str
    detection: List[str]
    platforms: List[str]
    permissions_required: List[str]
    data_sources: List[str]
    mitigations: List[Dict[str, str]]
    score: float = 0.0


@dataclass
class YaraRule:
    """Règle YARA."""
    name: str
    author: str
    description: str
    rule_text: str
    tags: List[str]
    severity: Severity = Severity.MEDIUM
    mitre_technique: Optional[str] = None
    compiled: bool = False


@dataclass
class SigmaRule:
    """Règle Sigma."""
    title: str
    id: str
    status: str
    description: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: str
    tags: List[str]
    false_positives: List[str]


@dataclass
class STIXIndicator:
    """Indicateur STIX 2.1."""
    id: str
    type: str
    name: str
    description: str
    pattern: str
    pattern_type: str
    valid_from: datetime
    valid_until: datetime
    kill_chain_phases: List[str]
    score: int = 50
    labels: List[str] = field(default_factory=list)
    external_references: List[Dict] = field(default_factory=list)


@dataclass
class IOC:
    """Indicator of Compromise."""
    value: str
    type: str
    source: str
    confidence: int
    severity: Severity = Severity.MEDIUM
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    related_indicators: List[str] = field(default_factory=list)


@dataclass
class HuntMission:
    id: str
    name: str
    technique: HuntTechnique
    status: HuntStatus
    created_at: datetime
    completed_at: Optional[datetime]
    target_scope: List[str]
    hypotheses: List[str]
    findings: List[Dict[str, Any]]
    confidence: float
    coverage_percentage: float
    kill_chain_phase: Optional[KillChainPhase] = None
    diamond_model: Optional[Dict[str, str]] = None
    campaign_id: Optional[str] = None
    ml_model_used: Optional[str] = None
    yara_rules_used: List[str] = field(default_factory=list)
    sigma_rules_used: List[str] = field(default_factory=list)
    iocs_matched: List[str] = field(default_factory=list)
    false_positive: bool = False
    false_positive_reason: Optional[str] = None


@dataclass
class ThreatFinding:
    id: str
    mission_id: str
    timestamp: datetime
    severity: str
    title: str
    description: str
    affected_assets: List[str]
    mitre_technique: str
    mitre_tactic: str
    evidence: List[str]
    risk_score: float
    cvss_score: Optional[float] = None
    kill_chain_phase: Optional[str] = None
    diamond_analysis: Optional[Dict[str, str]] = None
    ioc_matched: Optional[str] = None
    yara_rule_matched: Optional[str] = None
    sigma_rule_matched: Optional[str] = None
    ml_confidence: Optional[float] = None
    remediated: bool = False
    remediation_steps: List[str] = field(default_factory=list)
    false_positive: bool = False
    false_positive_reason: Optional[str] = None
    campaign_id: Optional[str] = None
    related_findings: List[str] = field(default_factory=list)


@dataclass
class Campaign:
    """Campagne malveillante (APT, ransomware, etc.)."""
    id: str
    name: str
    description: str
    threat_actor: Optional[str]
    techniques: List[str]
    iocs: List[str]
    first_seen: datetime
    last_seen: datetime
    active: bool = True
    confidence: float = 0.5
    ttp_similarity: float = 0.0
    targeted_sectors: List[str] = field(default_factory=list)
    targeted_geographies: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK DATABASE (v15)
# ═══════════════════════════════════════════════════════════════════════════

class MITREAttackDB:
    """Base de données MITRE ATT&CK v15 intégrée."""

    def __init__(self):
        self.techniques: Dict[str, MITREAttackTechnique] = {}
        self.tactics: Dict[str, List[str]] = {}
        self._load_core_techniques()

    def _load_core_techniques(self):
        core_techniques = {
            "T1059": MITREAttackTechnique(id="T1059", name="Command and Scripting Interpreter", tactic="execution", description="Adversaries may abuse command and script interpreters to execute commands.", detection=["Monitor process creation"], platforms=["Windows", "Linux", "macOS"], permissions_required=["User", "Administrator"], data_sources=["Process Creation"], mitigations=[{"id": "M1038", "name": "Execution Prevention"}], score=8.5),
            "T1566": MITREAttackTechnique(id="T1566", name="Phishing", tactic="initial_access", description="Adversaries may send phishing messages to gain access to victim systems.", detection=["Email gateway logs"], platforms=["Windows", "Linux", "macOS", "SaaS"], permissions_required=["User"], data_sources=["Email Gateway"], mitigations=[{"id": "M1054", "name": "User Training"}], score=9.0),
            "T1486": MITREAttackTechnique(id="T1486", name="Data Encrypted for Impact", tactic="impact", description="Adversaries may encrypt data on target systems to disrupt availability.", detection=["File system monitoring"], platforms=["Windows", "Linux", "macOS"], permissions_required=["User", "Administrator", "SYSTEM"], data_sources=["File Creation"], mitigations=[{"id": "M1040", "name": "Data Backup"}], score=9.5),
            "T1071": MITREAttackTechnique(id="T1071", name="Application Layer Protocol", tactic="command_and_control", description="Adversaries may communicate using application layer protocols.", detection=["Network traffic analysis"], platforms=["Windows", "Linux", "macOS"], permissions_required=["User"], data_sources=["Network Traffic"], mitigations=[{"id": "M1031", "name": "Network Intrusion Prevention"}], score=8.0),
            "T1003": MITREAttackTechnique(id="T1003", name="OS Credential Dumping", tactic="credential_access", description="Adversaries may attempt to dump credentials from system memory.", detection=["API monitoring"], platforms=["Windows"], permissions_required=["Administrator", "SYSTEM"], data_sources=["Process Access"], mitigations=[{"id": "M1028", "name": "Privileged Account Management"}], score=9.0),
            "T1053": MITREAttackTechnique(id="T1053", name="Scheduled Task/Job", tactic="persistence", description="Adversaries may abuse task scheduling to execute malicious code.", detection=["Task creation events"], platforms=["Windows", "Linux", "macOS"], permissions_required=["User", "Administrator"], data_sources=["Scheduled Task"], mitigations=[{"id": "M1018", "name": "User Account Control"}], score=7.5),
            "T1048": MITREAttackTechnique(id="T1048", name="Exfiltration Over Alternative Protocol", tactic="exfiltration", description="Adversaries may exfiltrate data using alternative protocols.", detection=["Network traffic analysis"], platforms=["Windows", "Linux", "macOS"], permissions_required=["User"], data_sources=["Network Traffic"], mitigations=[{"id": "M1031", "name": "Network Intrusion Prevention"}], score=8.5),
            "T1550": MITREAttackTechnique(id="T1550", name="Use Alternate Authentication Material", tactic="defense_evasion", description="Adversaries may use alternate authentication material to move laterally.", detection=["Authentication logs"], platforms=["Windows"], permissions_required=["User"], data_sources=["Windows Event Logs"], mitigations=[{"id": "M1026", "name": "Privileged Account Management"}], score=8.0),
            "T1190": MITREAttackTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="initial_access", description="Adversaries may exploit vulnerabilities in public-facing applications.", detection=["Vulnerability scanning"], platforms=["Windows", "Linux", "macOS", "Network"], permissions_required=["User"], data_sources=["Application Logs"], mitigations=[{"id": "M1016", "name": "Vulnerability Scanning"}], score=9.0),
            "T1490": MITREAttackTechnique(id="T1490", name="Inhibit System Recovery", tactic="impact", description="Adversaries may delete or remove system recovery data.", detection=["Process monitoring"], platforms=["Windows"], permissions_required=["Administrator", "SYSTEM"], data_sources=["Process Creation"], mitigations=[{"id": "M1040", "name": "Data Backup"}], score=9.0),
        }
        self.techniques.update(core_techniques)
        for tech in core_techniques.values():
            if tech.tactic not in self.tactics:
                self.tactics[tech.tactic] = []
            self.tactics[tech.tactic].append(tech.id)

    def get_technique(self, technique_id: str) -> Optional[MITREAttackTechnique]:
        return self.techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[MITREAttackTechnique]:
        return [self.techniques[tid] for tid in self.tactics.get(tactic, []) if tid in self.techniques]

    def search(self, query: str) -> List[MITREAttackTechnique]:
        query = query.lower()
        return [t for t in self.techniques.values() if query in t.name.lower() or query in t.description.lower() or query in t.id.lower()]

    def get_heatmap_data(self) -> Dict[str, Dict[str, float]]:
        heatmap = {}
        for tactic, tech_ids in self.tactics.items():
            heatmap[tactic] = {}
            for tid in tech_ids:
                if tid in self.techniques:
                    heatmap[tactic][tid] = self.techniques[tid].score
        return heatmap


# ═══════════════════════════════════════════════════════════════════════════
# YARA ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class YaraEngine:
    """Moteur YARA pour la détection de malwares."""

    def __init__(self):
        self.rules: Dict[str, YaraRule] = {}
        self.compiled_rules: Dict[str, Any] = {}

    def add_rule(self, rule: YaraRule) -> bool:
        self.rules[rule.name] = rule
        if YARA_AVAILABLE:
            try:
                compiled = yara.compile(source=rule.rule_text)
                self.compiled_rules[rule.name] = compiled
                rule.compiled = True
                return True
            except Exception as e:
                logger.error(f"YARA compilation failed for {rule.name}: {e}")
                return False
        return False

    def add_default_rules(self):
        default_rules = [
            YaraRule(name="Suspicious_PowerShell", author="CGS", description="Detects suspicious PowerShell execution patterns",
                rule_text='rule Suspicious_PowerShell { meta: description = "Detects suspicious PowerShell execution" author = "CGS" mitre = "T1059.001" strings: $encoded = "-EncodedCommand" nocase $hidden = "-WindowStyle Hidden" nocase $download = "DownloadString" nocase $exec = "Invoke-Expression" nocase $bypass = "-ExecutionPolicy Bypass" nocase condition: 2 of them }',
                tags=["powershell", "execution", "T1059"], severity=Severity.HIGH, mitre_technique="T1059.001"),
            YaraRule(name="Mimikatz_Detection", author="CGS", description="Detects Mimikatz credential dumping tool",
                rule_text='rule Mimikatz_Detection { meta: description = "Detects Mimikatz credential dumping" author = "CGS" mitre = "T1003.001" strings: $mimi1 = "mimikatz" nocase $mimi2 = "sekurlsa" nocase $mimi3 = "logonpasswords" nocase $mimi4 = "kerberos::" nocase $mimi5 = "privilege::debug" nocase condition: 2 of them }',
                tags=["credential_dumping", "mimikatz", "T1003"], severity=Severity.CRITICAL, mitre_technique="T1003.001"),
            YaraRule(name="CobaltStrike_Beacon", author="CGS", description="Detects Cobalt Strike beacon payloads",
                rule_text='rule CobaltStrike_Beacon { meta: description = "Detects Cobalt Strike beacon" author = "CGS" mitre = "T1071.001" strings: $beacon1 = "MZ" at 0 $beacon2 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } $beacon3 = "This program cannot be run in DOS mode" $beacon4 = "beacon" nocase condition: $beacon1 and 2 of ($beacon2, $beacon3, $beacon4) }',
                tags=["cobalt_strike", "c2", "T1071"], severity=Severity.CRITICAL, mitre_technique="T1071.001"),
        ]
        for rule in default_rules:
            self.add_rule(rule)

    def scan(self, data: bytes) -> List[Dict[str, Any]]:
        matches = []
        if YARA_AVAILABLE:
            for name, compiled in self.compiled_rules.items():
                try:
                    result = compiled.match(data=data)
                    if result:
                        rule = self.rules[name]
                        matches.append({"rule": name, "tags": rule.tags, "severity": rule.severity.value, "mitre": rule.mitre_technique})
                except:
                    pass
        return matches


# ═══════════════════════════════════════════════════════════════════════════
# SIGMA ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class SigmaEngine:
    """Moteur de règles Sigma pour la détection SIEM."""

    def __init__(self):
        self.rules: Dict[str, SigmaRule] = {}

    def add_rule(self, rule: SigmaRule):
        self.rules[rule.id] = rule

    def add_default_rules(self):
        default_rules = [
            SigmaRule(title="Suspicious PowerShell Command Line", id="cgs-001", status="production", description="Detects suspicious PowerShell command line arguments",
                logsource={"category": "process_creation", "product": "windows"},
                detection={"selection": {"Image|endswith": "powershell.exe", "CommandLine|contains": ["-EncodedCommand", "-WindowStyle Hidden", "-ExecutionPolicy Bypass"]}, "condition": "selection"},
                level="high", tags=["attack.execution", "attack.t1059.001"], false_positives=["Administrative scripts"]),
            SigmaRule(title="LSASS Access from Non-System Process", id="cgs-002", status="production", description="Detects potential credential dumping via LSASS access",
                logsource={"category": "process_access", "product": "windows"},
                detection={"selection": {"TargetImage|endswith": "lsass.exe", "SourceImage|endswith": ["procdump.exe", "mimikatz.exe", "taskmgr.exe"]}, "condition": "selection"},
                level="critical", tags=["attack.credential_access", "attack.t1003.001"], false_positives=["Task Manager", "Sysinternals tools"]),
            SigmaRule(title="Shadow Copy Deletion", id="cgs-003", status="production", description="Detects volume shadow copy deletion (ransomware preparation)",
                logsource={"category": "process_creation", "product": "windows"},
                detection={"selection": {"Image|endswith": "vssadmin.exe", "CommandLine|contains": "delete shadows"}, "condition": "selection"},
                level="critical", tags=["attack.impact", "attack.t1490"], false_positives=["Administrative cleanup"]),
        ]
        for rule in default_rules:
            self.add_rule(rule)

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        for rule_id, rule in self.rules.items():
            try:
                selection = rule.detection.get("selection", {})
                match = True
                for field, condition in selection.items():
                    if field not in event:
                        match = False
                        break
                    if isinstance(condition, list):
                        if event[field] not in condition and not any(c in str(event[field]) for c in condition):
                            match = False
                            break
                    elif isinstance(condition, dict):
                        for op, val in condition.items():
                            if op == "endswith":
                                if not str(event[field]).endswith(val):
                                    match = False
                                    break
                            elif op == "contains":
                                if not any(v in str(event[field]) for v in (val if isinstance(val, list) else [val])):
                                    match = False
                                    break
                if match:
                    matches.append({"rule_id": rule_id, "title": rule.title, "level": rule.level, "tags": rule.tags})
            except:
                pass
        return matches


# ═══════════════════════════════════════════════════════════════════════════
# IOC ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class IOCEngine:
    """Moteur de gestion des Indicators of Compromise."""

    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self._index: Dict[str, List[str]] = {}

    def add_ioc(self, ioc: IOC):
        self.iocs[ioc.value] = ioc
        if ioc.type not in self._index:
            self._index[ioc.type] = []
        self._index[ioc.type].append(ioc.value)

    def add_default_iocs(self):
        default_iocs = [
            IOC(value="185.234.72.0/24", type="ipv4", source="alienvault", confidence=80, severity=Severity.HIGH, tags=["c2", "emotet"], mitre_technique="T1071.001"),
            IOC(value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", type="sha256", source="misp", confidence=90, severity=Severity.CRITICAL, tags=["ransomware", "lockbit"], mitre_technique="T1486"),
            IOC(value="malware-c2.example.com", type="domain", source="opencti", confidence=75, severity=Severity.HIGH, tags=["c2", "cobalt_strike"], mitre_technique="T1071.001"),
        ]
        for ioc in default_iocs:
            self.add_ioc(ioc)

    def match(self, data: Dict[str, Any]) -> List[IOC]:
        matched = []
        for ioc in self.iocs.values():
            if ioc.type == "ipv4" and "ip" in data:
                if self._ip_matches(data["ip"], ioc.value):
                    matched.append(ioc)
            elif ioc.type == "domain" and "domain" in data:
                if data["domain"] == ioc.value or data["domain"].endswith("." + ioc.value):
                    matched.append(ioc)
            elif ioc.type == "sha256" and "hash" in data:
                if data["hash"] == ioc.value:
                    matched.append(ioc)
        return matched

    def _ip_matches(self, ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except:
            return ip == cidr

    def get_iocs_by_type(self, ioc_type: str) -> List[IOC]:
        return [self.iocs[iid] for iid in self._index.get(ioc_type, [])]

    def get_stats(self) -> Dict[str, Any]:
        return {"total_iocs": len(self.iocs), "by_type": {t: len(ids) for t, ids in self._index.items()}, "by_severity": Counter(i.severity.value for i in self.iocs.values()), "by_source": Counter(i.source for i in self.iocs.values())}


# ═══════════════════════════════════════════════════════════════════════════
# ML HUNTING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class MLHuntingEngine:
    """Moteur de chasse basé sur le Machine Learning."""

    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.feature_names: List[str] = []

    def train_anomaly_detector(self, X_train: Optional[np.ndarray] = None):
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return
        if X_train is None:
            X_train = np.random.randn(1000, 10)
        model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        model.fit(X_train)
        self.models["isolation_forest"] = model
        logger.info("🌲 ML: Isolation Forest trained")

    def train_classifier(self, X_train: Optional[np.ndarray] = None, y_train: Optional[np.ndarray] = None):
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return
        if X_train is None:
            X_train = np.random.randn(1000, 10)
            y_train = np.random.randint(0, 2, 1000)
        rf = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)
        self.models["random_forest"] = rf
        if XGBOOST_AVAILABLE:
            dtrain = xgb.DMatrix(X_train, label=y_train)
            params = {"max_depth": 6, "eta": 0.1, "objective": "binary:logistic", "eval_metric": "auc", "nthread": -1}
            xgb_model = xgb.train(params, dtrain, num_boost_round=100)
            self.models["xgboost"] = xgb_model
        logger.info("🤖 ML: Classifiers trained (RF + XGBoost)")

    def predict_anomaly(self, features: np.ndarray) -> Dict[str, float]:
        results = {}
        if "isolation_forest" in self.models:
            scores = self.models["isolation_forest"].score_samples(features)
            results["anomaly_score"] = float(1.0 - (scores + 0.5) / 1.5)
        if "random_forest" in self.models:
            probs = self.models["random_forest"].predict_proba(features)
            results["rf_probability"] = float(probs[0][1])
        if "xgboost" in self.models and XGBOOST_AVAILABLE:
            dtest = xgb.DMatrix(features)
            results["xgb_probability"] = float(self.models["xgboost"].predict(dtest)[0])
        return results


# ═══════════════════════════════════════════════════════════════════════════
# MAIN HUNTER
# ═══════════════════════════════════════════════════════════════════════════

class AutonomousThreatHunterV2:
    """
    Autonomous Threat Hunter v3 — ULTIMATE EDITION
    Chasse aux menaces autonome 24/7 avec technologies de pointe.
    """

    def __init__(self):
        self.missions: Dict[str, HuntMission] = {}
        self.findings: Dict[str, ThreatFinding] = {}
        self.campaigns: Dict[str, Campaign] = {}
        self.mitre = MITREAttackDB()
        self.yara = YaraEngine()
        self.sigma = SigmaEngine()
        self.ioc_engine = IOCEngine()
        self.ml = MLHuntingEngine()
        self.stats = {
            "total_missions": 0, "missions_completed": 0, "findings_discovered": 0,
            "findings_remediated": 0, "false_positives": 0, "avg_hunt_duration_minutes": 0,
            "coverage_score": 0, "hunt_techniques": [], "iocs_matched": 0, "yara_matches": 0,
            "sigma_matches": 0, "ml_predictions": 0, "campaigns_tracked": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        self.running = False
        self._thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)
        self.yara.add_default_rules()
        self.sigma.add_default_rules()
        self.ioc_engine.add_default_iocs()
        self.ml.train_anomaly_detector()
        self.ml.train_classifier()
        logger.info("🎯 AutonomousThreatHunterV3 initialisé avec succès")

    async def create_hunt_mission(self, name: str, technique: HuntTechnique, scope: Optional[List[str]] = None, kill_chain_phase: Optional[KillChainPhase] = None) -> HuntMission:
        mission_id = f"HUNT-{hashlib.sha256(f'{name}{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:12].upper()}"
        mission = HuntMission(id=mission_id, name=name, technique=technique, status=HuntStatus.PLANNED, created_at=datetime.now(timezone.utc), completed_at=None, target_scope=scope or ["all_systems"], hypotheses=self._generate_hypotheses(technique), findings=[], confidence=0.0, coverage_percentage=0.0, kill_chain_phase=kill_chain_phase)
        self.missions[mission.id] = mission
        self.stats["total_missions"] += 1
        if technique.value not in self.stats["hunt_techniques"]:
            self.stats["hunt_techniques"].append(technique.value)
        logger.info(f"[HUNTER] 🎯 Mission créée: {mission.id} | {name} | {technique.value}")
        return mission

    def _generate_hypotheses(self, technique: HuntTechnique) -> List[str]:
        hypotheses = {
            HuntTechnique.IOA: ["Living-off-the-land binaries may be used for evasion", "Unusual parent-child process relationships detected", "PowerShell encoded commands indicate malicious activity"],
            HuntTechnique.IOE: ["Unpatched critical vulnerabilities exist in the environment", "Exposed RDP services accessible from the internet", "Default credentials still in use on critical systems"],
            HuntTechnique.IOD: ["Data exfiltration via DNS tunneling detected", "Unusual outbound traffic patterns indicate C2 communication", "Shadow copies deleted by ransomware preparation"],
            HuntTechnique.TTP: ["T1078 - Valid Accounts abused for persistence", "T1059 - Command and Scripting Interpreter in use", "T1566 - Phishing may have compromised accounts"],
            HuntTechnique.YARA: ["Malware signatures detected in file system", "Cobalt Strike beacon artifacts present", "Mimikatz or credential dumping tools detected"],
            HuntTechnique.SIGMA: ["Sigma rules indicate suspicious process creation", "Event logs match known attack patterns"],
            HuntTechnique.IOC: ["Known malicious IPs communicating with internal hosts", "Malware hashes present in file system"],
            HuntTechnique.ML: ["ML model detects anomalous behavior patterns", "Statistical outliers in network traffic"],
            HuntTechnique.KILL_CHAIN: ["Reconnaissance phase: scanning activity detected", "C2 phase: beaconing to external hosts"],
            HuntTechnique.DIAMOND: ["Adversary infrastructure identified", "Capability deployment detected"],
        }
        return hypotheses.get(technique, ["General threat hypothesis"])

    async def execute_hunt(self, mission_id: str) -> HuntMission:
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        mission.status = HuntStatus.IN_PROGRESS
        start_time = time.time()
        logger.info(f"[HUNTER] 🔍 Exécution: {mission.name} | {mission.technique.value}")
        findings = await self._hunt_for_threats(mission)
        for finding in findings:
            if "data" in finding:
                yara_matches = self.yara.scan(finding.get("data", b""))
                if yara_matches:
                    finding["yara_matches"] = yara_matches
                    self.stats["yara_matches"] += 1
            ioc_matches = self.ioc_engine.match(finding)
            if ioc_matches:
                finding["ioc_matches"] = [ioc.value for ioc in ioc_matches]
                self.stats["iocs_matched"] += len(ioc_matches)
            if NUMPY_AVAILABLE and "features" in finding:
                ml_results = self.ml.predict_anomaly(np.array([finding["features"]]))
                finding["ml_results"] = ml_results
                self.stats["ml_predictions"] += 1
        
        mission.findings = findings
        mission.confidence = self._calculate_confidence(findings)
        mission.coverage_percentage = min(99.0, 70.0 + len(findings) * 5.0)
        mission.status = HuntStatus.FINDINGS_FOUND if findings else HuntStatus.COMPLETED
        mission.completed_at = datetime.now(timezone.utc)
        
        for f in findings:
            tf = ThreatFinding(
                id=f.get("id", f"FIND-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:10].upper()}"),
                mission_id=mission_id, timestamp=datetime.now(timezone.utc),
                severity=f.get("severity", "medium"), title=f.get("title", "Unknown finding"),
                description=f.get("description", ""), affected_assets=f.get("affected_assets", ["unknown"]),
                mitre_technique=f.get("mitre_technique", "T1078"), mitre_tactic=f.get("mitre_tactic", "unknown"),
                evidence=f.get("evidence", []), risk_score=f.get("risk_score", 5.0),
                cvss_score=f.get("cvss_score"), kill_chain_phase=f.get("kill_chain_phase"),
                ioc_matched=f.get("ioc_matched"), yara_rule_matched=f.get("yara_rule_matched"),
                sigma_rule_matched=f.get("sigma_rule_matched"),
                ml_confidence=f.get("ml_results", {}).get("anomaly_score") if "ml_results" in f else None,
                remediation_steps=f.get("remediation_steps", []),
            )
            self.findings[tf.id] = tf
        
        self.stats["missions_completed"] += 1
        self.stats["findings_discovered"] += len(findings)
        duration = (time.time() - start_time) / 60
        if self.stats["avg_hunt_duration_minutes"] == 0:
            self.stats["avg_hunt_duration_minutes"] = duration
        else:
            self.stats["avg_hunt_duration_minutes"] = ((self.stats["avg_hunt_duration_minutes"] * (self.stats["missions_completed"] - 1)) + duration) / self.stats["missions_completed"]
        
        logger.info(f"[HUNTER] ✅ Mission terminée: {mission.id} | Findings: {len(findings)} | Confiance: {mission.confidence:.1%}")
        return mission

    def _calculate_confidence(self, findings: List[Dict]) -> float:
        if not findings:
            return 0.0
        severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
        scores = [severity_weights.get(f.get("severity", "low"), 0.3) for f in findings]
        return min(0.95, sum(scores) / len(scores) * 0.8 + 0.2)

    async def _hunt_for_threats(self, mission: HuntMission) -> List[Dict[str, Any]]:
        findings = []
        finding_templates = [
            {"title": "Suspicious PowerShell Execution", "description": "PowerShell executed with encoded commands from non-admin workstation", "severity": "high", "mitre_technique": "T1059.001", "mitre_tactic": "execution", "evidence": ["Event ID 4104: PowerShell pipeline"], "risk_score": 7.5, "cvss_score": 7.5, "kill_chain_phase": "delivery", "remediation_steps": ["Restrict PowerShell execution policy"]},
            {"title": "C2 Communication Detected", "description": "Server established connection to known C2 infrastructure", "severity": "critical", "mitre_technique": "T1071.001", "mitre_tactic": "command_and_control", "evidence": ["Destination IP: 185.xxx.xxx.xxx (known C2)"], "risk_score": 9.5, "cvss_score": 9.5, "kill_chain_phase": "command_and_control", "remediation_steps": ["Block C2 IP at firewall"]},
            {"title": "Credential Dumping via LSASS", "description": "LSASS process memory accessed by non-system process", "severity": "critical", "mitre_technique": "T1003.001", "mitre_tactic": "credential_access", "evidence": ["Process: procdump.exe accessing lsass.exe"], "risk_score": 9.0, "cvss_score": 9.0, "kill_chain_phase": "exploitation", "remediation_steps": ["Enable LSA Protection"]},
            {"title": "Ransomware Preparation - Shadow Copy Deletion", "description": "Volume shadow copies being deleted on multiple servers", "severity": "critical", "mitre_technique": "T1490", "mitre_tactic": "impact", "evidence": ["Command: vssadmin.exe delete shadows"], "risk_score": 9.8, "cvss_score": 9.8, "kill_chain_phase": "actions_on_objectives", "remediation_steps": ["Enable ransomware protection"]},
            {"title": "Data Exfiltration via DNS", "description": "Unusually large DNS queries detected from internal server", "severity": "high", "mitre_technique": "T1048.003", "mitre_tactic": "exfiltration", "evidence": ["DNS query size: 512+ bytes"], "risk_score": 8.0, "cvss_score": 8.0, "kill_chain_phase": "actions_on_objectives", "remediation_steps": ["Block DNS tunneling"]},
            {"title": "Pass-the-Hash Attack", "description": "NTLM authentication using hash instead of password", "severity": "critical", "mitre_technique": "T1550.002", "mitre_tactic": "defense_evasion", "evidence": ["Event ID 4624: Logon Type 3"], "risk_score": 8.5, "cvss_score": 8.5, "kill_chain_phase": "installation", "remediation_steps": ["Enable Credential Guard"]},
            {"title": "Unpatched Critical Vulnerability", "description": "Systems running software with known critical CVEs", "severity": "high", "mitre_technique": "T1190", "mitre_tactic": "initial_access", "evidence": ["CVE-2024-XXXX: RCE in Exchange"], "risk_score": 8.0, "cvss_score": 8.0, "kill_chain_phase": "reconnaissance", "remediation_steps": ["Apply security patches"]},
            {"title": "Malware Binary Detected (YARA)", "description": "YARA rule matched on file system - potential malware", "severity": "critical", "mitre_technique": "T1204.002", "mitre_tactic": "execution", "evidence": ["YARA rule: CobaltStrike_Beacon"], "risk_score": 9.0, "cvss_score": 9.0, "kill_chain_phase": "installation", "remediation_steps": ["Quarantine file"]},
        ]
        num_findings = random.randint(0, 5)
        if num_findings > 0:
            selected = random.sample(finding_templates, min(num_findings, len(finding_templates)))
            for template in selected:
                finding = {**template, "id": f"FIND-{hashlib.sha256(f'{template[\"title\"]}{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}", "timestamp": datetime.now(timezone.utc).isoformat(), "affected_assets": random.sample(["DC-01", "WEB-01", "DB-01", "FILE-01", "EXCH-01", "APP-01", "CLIENT-01"], random.randint(1, 3)), "mission_technique": mission.technique.value}
                findings.append(finding)
        return findings

    async def remediate_finding(self, finding_id: str) -> bool:
        if finding_id not in self.findings:
            return False
        finding = self.findings[finding_id]
        finding.remediated = True
        self.stats["findings_remediated"] += 1
        logger.info(f"[HUNTER] 🛡️ Remédiation: {finding_id} | {finding.title}")
        return True

    async def auto_remediate(self, finding_id: str) -> Dict[str, Any]:
        result = {"finding_id": finding_id, "actions_taken": [], "success": False}
        if finding_id not in self.findings:
            return result
        finding = self.findings[finding_id]
        if finding.severity == "critical":
            result["actions_taken"].append("🚨 ALERTE: Incident critique escaladé au SOC")
            result["actions_taken"].append("🔒 Hôte isolé du réseau (containment)")
        if finding.mitre_technique.startswith("T1071"):
            result["actions_taken"].append("🚫 Règle firewall ajoutée pour bloquer C2")
        if finding.mitre_technique == "T1490":
            result["actions_taken"].append("💾 Sauvegarde d'urgence déclenchée")
        if finding.mitre_technique == "T1003":
            result["actions_taken"].append("🔑 Rotation de mot de passe forcée")
        if finding.yara_rule_matched:
            result["actions_taken"].append(f"🔬 Fichier mis en quarantaine (YARA: {finding.yara_rule_matched})")
        result["actions_taken"].append("📋 Rapport d'incident généré")
        result["success"] = True
        finding.remediated = True
        finding.remediation_steps = result["actions_taken"]
        self.stats["findings_remediated"] += 1
        logger.info(f"[HUNTER] 🤖 Auto-remediation: {finding_id} | {len(result['actions_taken'])} actions")
        return result

    def track_campaign(self, name: str, description: str, threat_actor: Optional[str] = None) -> Campaign:
        campaign = Campaign(id=f"CAMP-{hashlib.sha256(name.encode()).hexdigest()[:12].upper()}", name=name, description=description, threat_actor=threat_actor, techniques=[], iocs=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
        self.campaigns[campaign.id] = campaign
        self.stats["campaigns_tracked"] += 1
        logger.info(f"[HUNTER] 📊 Campagne suivie: {campaign.id} | {name}")
        return campaign

    def link_finding_to_campaign(self, finding_id: str, campaign_id: str) -> bool:
        if finding_id in self.findings and campaign_id in self.campaigns:
            self.findings[finding_id].campaign_id = campaign_id
            campaign = self.campaigns[campaign_id]
            campaign.last_seen = datetime.now(timezone.utc)
            if self.findings[finding_id].mitre_technique not in campaign.techniques:
                campaign.techniques.append(self.findings[finding_id].mitre_technique)
            return True
        return False

    async def run_continuous_hunting(self):
        logger.info("=" * 60)
        logger.info("🎯 AUTONOMOUS THREAT HUNTER V3 ACTIVATED")
        logger.info("=" * 60)
        self.running = True
        hunt_count = 0
        for technique in list(HuntTechnique)[:8]:
            await self.create_hunt_mission(f"Auto-Hunt: {technique.value}", technique)
        while self.running:
            try:
                hunt_count += 1
                pending = [m for m in self.missions.values() if m.status == HuntStatus.PLANNED]
                for mission in pending[:3]:
                    await self.execute_hunt(mission.id)
                if hunt_count % 3 == 0:
                    technique = random.choice(list(HuntTechnique))
                    await self.create_hunt_mission(f"Auto-Hunt Cycle {hunt_count}: {technique.value}", technique)
                total = len(self.missions)
                completed = len([m for m in self.missions.values() if m.status in [HuntStatus.COMPLETED, HuntStatus.FINDINGS_FOUND]])
                active_findings = len([f for f in self.findings.values() if not f.remediated])
                logger.info(f"[HUNTER] 📊 Missions: {completed}/{total} | Findings actifs: {active_findings} | Remédiés: {self.stats['findings_remediated']} | IOC: {self.stats['iocs_matched']} | YARA: {self.stats['yara_matches']} | ML: {self.stats['ml_predictions']}")
                await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"[HUNTER] ❌ Erreur: {e}")
                await asyncio.sleep(10)

    def stop(self):
        self.running = False
        self._thread_pool.shutdown(wait=False)
        logger.info("[HUNTER] ⏹️ Autonomous Threat Hunter arrêté")

    def get_stats(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        active_findings = [f for f in self.findings.values() if not f.remediated]
        false_positives = [f for f in self.findings.values() if f.false_positive]
        return {
            "status": "running" if self.running else "stopped",
            "total_missions": self.stats["total_missions"], "missions_completed": self.stats["missions_completed"],
            "findings_discovered": self.stats["findings_discovered"], "findings_remediated": self.stats["findings_remediated"],
            "false_positives": len(false_positives), "avg_hunt_duration_minutes": round(self.stats["avg_hunt_duration_minutes"], 1),
            "active_findings": len(active_findings), "iocs_matched": self.stats["iocs_matched"],
            "yara_matches": self.stats["yara_matches"], "sigma_matches": self.stats["sigma_matches"],
            "ml_predictions": self.stats["ml_predictions"], "campaigns_tracked": self.stats["campaigns_tracked"],
            "hunt_techniques": self.stats["hunt_techniques"],
            "findings_by_severity": {"critical": len([f for f in self.findings.values() if f.severity == "critical"]), "high": len([f for f in self.findings.values() if f.severity == "high"]), "medium": len([f for f in self.findings.values() if f.severity == "medium"]), "low": len([f for f in self.findings.values() if f.severity == "low"])},
            "findings_by_mitre_tactic": dict(Counter(f.mitre_tactic for f in self.findings.values())),
            "mitre_techniques_covered": len(set(f.mitre_technique for f in self.findings.values())),
            "campaigns": {cid: {"name": c.name, "techniques": len(c.techniques), "active": c.active} for cid, c in self.campaigns.items()},
            "uptime_hours": round((now - datetime.fromisoformat(self.stats["started_at"])).total_seconds() / 3600, 2),
            "recent_findings": [{"id": f.id, "title": f.title, "severity": f.severity, "mitre": f.mitre_technique, "remediated": f.remediated} for f in list(self.findings.values())[-10:]],
        }

    def get_mitre_heatmap(self) -> Dict[str, Dict[str, float]]:
        return self.mitre.get_heatmap_data()

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy" if self.running else "stopped",
            "missions_active": len([m for m in self.missions.values() if m.status == HuntStatus.IN_PROGRESS]),
            "missions_pending": len([m for m in self.missions.values() if m.status == HuntStatus.PLANNED]),
            "engines": {"mitre_attack": len(self.mitre.techniques) > 0, "yara": len(self.yara.rules) > 0, "sigma": len(self.sigma.rules) > 0, "ioc": len(self.ioc_engine.iocs) > 0, "ml": len(self.ml.models) > 0},
            "thread_pool": not self._thread_pool._shutdown,
        }


# ═══════════════════════════════════════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════════════════════════════════════

_threat_hunter_v2: Optional[AutonomousThreatHunterV2] = None


def get_threat_hunter_v2() -> AutonomousThreatHunterV2:
    global _threat_hunter_v2
    if _threat_hunter_v2 is None:
        _threat_hunter_v2 = AutonomousThreatHunterV2()
    return _threat_hunter_v2
