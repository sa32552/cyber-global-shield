"""
Cyber Global Shield — Core Security Modules
Centralized exports for all security modules.
"""

import logging

logger = logging.getLogger(__name__)

# =============================================================================
# Essential imports — these MUST succeed for the app to function
# =============================================================================
from app.core.config import settings
from app.core.database import get_db, init_db
from app.core.security import create_access_token, verify_token, get_current_user

# =============================================================================
# Infrastructure modules — these are core and should load directly
# =============================================================================
from app.core.auth import auth_handler, AuthHandler
from app.core.middleware import setup_middleware
from app.core.websocket_manager import websocket_manager, WebSocketManager
from app.core.webhooks import webhook_manager, WebhookManager
from app.core.tenant import tenant_manager, TenantManager
from app.core.pagination import paginate
from app.core.notifications import notification_manager, NotificationManager
from app.core.export import export_manager, ExportManager
from app.core.search import search_engine, SearchEngine
from app.core.sso import sso_handler, SSOHandler
from app.core.llm_cost_monitor import llm_cost_monitor, LLMCostMonitor

# =============================================================================
# Security Modules — wrapped in try/except to prevent startup crashes
# =============================================================================

# Honeypot
try:
    from app.core.honeypot import honeypot_intelligence, HoneypotIntelligence
except ImportError as e:
    logger.warning("Failed to import honeypot module: %s", e)
    honeypot_intelligence = None
    HoneypotIntelligence = None

# Ransomware Shield
try:
    from app.core.ransomware_shield import ransomware_shield, RansomwareShield
except ImportError as e:
    logger.warning("Failed to import ransomware_shield module: %s", e)
    ransomware_shield = None
    RansomwareShield = None

# Zero Day Detector
try:
    from app.core.zero_day_detector import zero_day_detector, ZeroDayDetector
except ImportError as e:
    logger.warning("Failed to import zero_day_detector module: %s", e)
    zero_day_detector = None
    ZeroDayDetector = None

# Supply Chain Security
try:
    from app.core.supply_chain_security import supply_chain_security, SupplyChainSecurity
except ImportError as e:
    logger.warning("Failed to import supply_chain_security module: %s", e)
    supply_chain_security = None
    SupplyChainSecurity = None

# Deep Packet Inspector
try:
    from app.core.deep_packet_inspector import deep_packet_inspector, DeepPacketInspector
except ImportError as e:
    logger.warning("Failed to import deep_packet_inspector module: %s", e)
    deep_packet_inspector = None
    DeepPacketInspector = None

# Behavioral Biometrics
try:
    from app.core.behavioral_biometrics import behavioral_biometrics, BehavioralBiometrics
except ImportError as e:
    logger.warning("Failed to import behavioral_biometrics module: %s", e)
    behavioral_biometrics = None
    BehavioralBiometrics = None

# Dark Web Monitor
try:
    from app.core.dark_web_monitor import dark_web_monitor, DarkWebMonitor
except ImportError as e:
    logger.warning("Failed to import dark_web_monitor module: %s", e)
    dark_web_monitor = None
    DarkWebMonitor = None

# Automated Forensics
try:
    from app.core.automated_forensics import automated_forensics, AutomatedForensics
except ImportError as e:
    logger.warning("Failed to import automated_forensics module: %s", e)
    automated_forensics = None
    AutomatedForensics = None

# Threat Intel
try:
    from app.core.threat_intel import threat_intel, ThreatIntel
except ImportError as e:
    logger.warning("Failed to import threat_intel module: %s", e)
    threat_intel = None
    ThreatIntel = None

# AI Deception Grid
try:
    from app.core.ai_deception_grid import ai_deception_grid, AIDeceptionGrid
except ImportError as e:
    logger.warning("Failed to import ai_deception_grid module: %s", e)
    ai_deception_grid = None
    AIDeceptionGrid = None

# Self Healing
try:
    from app.core.self_healing import self_healing, SelfHealing
except ImportError as e:
    logger.warning("Failed to import self_healing module: %s", e)
    self_healing = None
    SelfHealing = None

# Quantum Crypto
try:
    from app.core.quantum_crypto import quantum_crypto, QuantumCrypto
except ImportError as e:
    logger.warning("Failed to import quantum_crypto module: %s", e)
    quantum_crypto = None
    QuantumCrypto = None

# Autonomous Threat Hunter
try:
    from app.core.autonomous_threat_hunter import autonomous_threat_hunter, AutonomousThreatHunter
except ImportError as e:
    logger.warning("Failed to import autonomous_threat_hunter module: %s", e)
    autonomous_threat_hunter = None
    AutonomousThreatHunter = None

# Blockchain Audit
try:
    from app.core.blockchain_audit import blockchain_audit, BlockchainAudit
except ImportError as e:
    logger.warning("Failed to import blockchain_audit module: %s", e)
    blockchain_audit = None
    BlockchainAudit = None

# Deepfake Detector
try:
    from app.core.deepfake_detector import deepfake_detector, DeepfakeDetector
except ImportError as e:
    logger.warning("Failed to import deepfake_detector module: %s", e)
    deepfake_detector = None
    DeepfakeDetector = None

# Automated Threat Modeling
try:
    from app.core.automated_threat_modeling import automated_threat_modeling, AutomatedThreatModeling
except ImportError as e:
    logger.warning("Failed to import automated_threat_modeling module: %s", e)
    automated_threat_modeling = None
    AutomatedThreatModeling = None

# Zero Trust Microseg
try:
    from app.core.zero_trust_microseg import zero_trust_microseg, ZeroTrustMicroseg
except ImportError as e:
    logger.warning("Failed to import zero_trust_microseg module: %s", e)
    zero_trust_microseg = None
    ZeroTrustMicroseg = None

# AI Code Auditor
try:
    from app.core.ai_code_auditor import ai_code_auditor, AICodeAuditor
except ImportError as e:
    logger.warning("Failed to import ai_code_auditor module: %s", e)
    ai_code_auditor = None
    AICodeAuditor = None

# Automated Compliance
try:
    from app.core.automated_compliance import automated_compliance, AutomatedCompliance
except ImportError as e:
    logger.warning("Failed to import automated_compliance module: %s", e)
    automated_compliance = None
    AutomatedCompliance = None

# Predictive Insurance
try:
    from app.core.predictive_insurance import predictive_insurance, PredictiveInsurance
except ImportError as e:
    logger.warning("Failed to import predictive_insurance module: %s", e)
    predictive_insurance = None
    PredictiveInsurance = None

# Digital Twin Security
try:
    from app.core.digital_twin_security import digital_twin_security, DigitalTwinSecurity
except ImportError as e:
    logger.warning("Failed to import digital_twin_security module: %s", e)
    digital_twin_security = None
    DigitalTwinSecurity = None

# Autonomous Pentest
try:
    from app.core.autonomous_pentest import autonomous_pentest, AutonomousPentest
except ImportError as e:
    logger.warning("Failed to import autonomous_pentest module: %s", e)
    autonomous_pentest = None
    AutonomousPentest = None

# Memory Forensics
try:
    from app.core.memory_forensics import memory_forensics, MemoryForensics
except ImportError as e:
    logger.warning("Failed to import memory_forensics module: %s", e)
    memory_forensics = None
    MemoryForensics = None

# Network Traffic Analyzer
try:
    from app.core.network_traffic_analyzer import network_traffic_analyzer, NetworkTrafficAnalyzer
except ImportError as e:
    logger.warning("Failed to import network_traffic_analyzer module: %s", e)
    network_traffic_analyzer = None
    NetworkTrafficAnalyzer = None

# Mobile Security Scanner
try:
    from app.core.mobile_security_scanner import mobile_scanner, MobileSecurityScanner
except ImportError as e:
    logger.warning("Failed to import mobile_security_scanner module: %s", e)
    mobile_scanner = None
    MobileSecurityScanner = None

# Cloud Security Posture
try:
    from app.core.cloud_security_posture import cloud_security_posture, CloudSecurityPosture
except ImportError as e:
    logger.warning("Failed to import cloud_security_posture module: %s", e)
    cloud_security_posture = None
    CloudSecurityPosture = None

# Secrets Detection
try:
    from app.core.secrets_detection import secrets_detection, SecretsDetectionEngine
except ImportError as e:
    logger.warning("Failed to import secrets_detection module: %s", e)
    secrets_detection = None
    SecretsDetectionEngine = None

# Security Dashboard API
try:
    from app.core.security_dashboard_api import security_dashboard_api, SecurityDashboardAPI
except ImportError as e:
    logger.warning("Failed to import security_dashboard_api module: %s", e)
    security_dashboard_api = None
    SecurityDashboardAPI = None

# Performance Optimizer
try:
    from app.core.performance_optimizer import performance_optimizer, PerformanceOptimizer
except ImportError as e:
    logger.warning("Failed to import performance_optimizer module: %s", e)
    performance_optimizer = None
    PerformanceOptimizer = None

# =============================================================================
# Quantum Modules — wrapped in try/except
# =============================================================================

try:
    from app.core.quantum_threat_intel import quantum_threat_intel, QuantumThreatIntel
except ImportError as e:
    logger.warning("Failed to import quantum_threat_intel module: %s", e)
    quantum_threat_intel = None
    QuantumThreatIntel = None

try:
    from app.core.quantum_dark_web import quantum_dark_web, QuantumDarkWebMonitor
except ImportError as e:
    logger.warning("Failed to import quantum_dark_web module: %s", e)
    quantum_dark_web = None
    QuantumDarkWebMonitor = None

try:
    from app.core.quantum_deepfake import quantum_deepfake, QuantumDeepfakeDetector
except ImportError as e:
    logger.warning("Failed to import quantum_deepfake module: %s", e)
    quantum_deepfake = None
    QuantumDeepfakeDetector = None

try:
    from app.core.quantum_insurance import quantum_insurance, QuantumInsurance
except ImportError as e:
    logger.warning("Failed to import quantum_insurance module: %s", e)
    quantum_insurance = None
    QuantumInsurance = None

try:
    from app.core.quantum_digital_twin import quantum_digital_twin, QuantumDigitalTwin
except ImportError as e:
    logger.warning("Failed to import quantum_digital_twin module: %s", e)
    quantum_digital_twin = None
    QuantumDigitalTwin = None

try:
    from app.core.quantum_blockchain import quantum_blockchain, QuantumBlockchain
except ImportError as e:
    logger.warning("Failed to import quantum_blockchain module: %s", e)
    quantum_blockchain = None
    QuantumBlockchain = None

try:
    from app.core.quantum_pentest import quantum_pentest, QuantumPentest
except ImportError as e:
    logger.warning("Failed to import quantum_pentest module: %s", e)
    quantum_pentest = None
    QuantumPentest = None

try:
    from app.core.quantum_memory_forensics import quantum_memory_forensics, QuantumMemoryForensics
except ImportError as e:
    logger.warning("Failed to import quantum_memory_forensics module: %s", e)
    quantum_memory_forensics = None
    QuantumMemoryForensics = None

try:
    from app.core.quantum_network_analyzer import quantum_network_analyzer, QuantumNetworkAnalyzer
except ImportError as e:
    logger.warning("Failed to import quantum_network_analyzer module: %s", e)
    quantum_network_analyzer = None
    QuantumNetworkAnalyzer = None

try:
    from app.core.quantum_mobile_scanner import quantum_mobile_scanner, QuantumMobileScanner
except ImportError as e:
    logger.warning("Failed to import quantum_mobile_scanner module: %s", e)
    quantum_mobile_scanner = None
    QuantumMobileScanner = None

try:
    from app.core.quantum_cloud_security import quantum_cloud_scanner, QuantumCloudScanner
except ImportError as e:
    logger.warning("Failed to import quantum_cloud_security module: %s", e)
    quantum_cloud_scanner = None
    QuantumCloudScanner = None

try:
    from app.core.quantum_secrets import quantum_secrets, QuantumSecretsDetector
except ImportError as e:
    logger.warning("Failed to import quantum_secrets module: %s", e)
    quantum_secrets = None
    QuantumSecretsDetector = None

# =============================================================================
# Phase 5-10: Advanced Platform Modules — wrapped in try/except
# =============================================================================

try:
    from app.core.auto_soc_orchestrator import AutoSOCOrchestrator
except ImportError as e:
    logger.warning("Failed to import auto_soc_orchestrator module: %s", e)
    AutoSOCOrchestrator = None

try:
    from app.core.predictive_attack_engine import PredictiveAttackEngine
except ImportError as e:
    logger.warning("Failed to import predictive_attack_engine module: %s", e)
    PredictiveAttackEngine = None

try:
    from app.core.neural_security_mesh import NeuralSecurityMesh
except ImportError as e:
    logger.warning("Failed to import neural_security_mesh module: %s", e)
    NeuralSecurityMesh = None

try:
    from app.core.dark_web_intel_network import DarkWebIntelNetwork
except ImportError as e:
    logger.warning("Failed to import dark_web_intel_network module: %s", e)
    DarkWebIntelNetwork = None

try:
    from app.core.cyber_risk_quantification import CyberRiskQuantification
except ImportError as e:
    logger.warning("Failed to import cyber_risk_quantification module: %s", e)
    CyberRiskQuantification = None

try:
    from app.core.active_defense_countermeasures import ActiveDefenseCountermeasures
except ImportError as e:
    logger.warning("Failed to import active_defense_countermeasures module: %s", e)
    ActiveDefenseCountermeasures = None

try:
    from app.core.blockchain_trust_network import BlockchainTrustNetwork
except ImportError as e:
    logger.warning("Failed to import blockchain_trust_network module: %s", e)
    BlockchainTrustNetwork = None

try:
    from app.core.quantum_safe_security import QuantumSafeSecurity
except ImportError as e:
    logger.warning("Failed to import quantum_safe_security module: %s", e)
    QuantumSafeSecurity = None

try:
    from app.core.autonomous_threat_hunter_v2 import AutonomousThreatHunterV2
except ImportError as e:
    logger.warning("Failed to import autonomous_threat_hunter_v2 module: %s", e)
    AutonomousThreatHunterV2 = None

try:
    from app.core.global_soc_dashboard import GlobalSOCDashboard
except ImportError as e:
    logger.warning("Failed to import global_soc_dashboard module: %s", e)
    GlobalSOCDashboard = None

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "settings", "get_db", "init_db",
    "create_access_token", "verify_token", "get_current_user",
    # Security Modules
    "honeypot_intelligence", "HoneypotIntelligence",
    "ransomware_shield", "RansomwareShield",
    "zero_day_detector", "ZeroDayDetector",
    "supply_chain_security", "SupplyChainSecurity",
    "deep_packet_inspector", "DeepPacketInspector",
    "behavioral_biometrics", "BehavioralBiometrics",
    "dark_web_monitor", "DarkWebMonitor",
    "automated_forensics", "AutomatedForensics",
    "threat_intel", "ThreatIntel",
    "ai_deception_grid", "AIDeceptionGrid",
    "self_healing", "SelfHealing",
    "quantum_crypto", "QuantumCrypto",
    "autonomous_threat_hunter", "AutonomousThreatHunter",
    "blockchain_audit", "BlockchainAudit",
    "deepfake_detector", "DeepfakeDetector",
    "automated_threat_modeling", "AutomatedThreatModeling",
    "zero_trust_microseg", "ZeroTrustMicroseg",
    "ai_code_auditor", "AICodeAuditor",
    "automated_compliance", "AutomatedCompliance",
    "predictive_insurance", "PredictiveInsurance",
    "digital_twin_security", "DigitalTwinSecurity",
    "autonomous_pentest", "AutonomousPentest",
    "memory_forensics", "MemoryForensics",
    "network_traffic_analyzer", "NetworkTrafficAnalyzer",
    "mobile_scanner", "MobileSecurityScanner",
    "cloud_security_posture", "CloudSecurityPosture",
    "secrets_detection", "SecretsDetectionEngine",
    "security_dashboard_api", "SecurityDashboardAPI",
    "performance_optimizer", "PerformanceOptimizer",
    # Infrastructure
    "auth_handler", "AuthHandler",
    "setup_middleware",
    "websocket_manager", "WebSocketManager",
    "webhook_manager", "WebhookManager",
    "tenant_manager", "TenantManager",
    "paginate",
    "notification_manager", "NotificationManager",
    "export_manager", "ExportManager",
    "search_engine", "SearchEngine",
    "sso_handler", "SSOHandler",
    "llm_cost_monitor", "LLMCostMonitor",
    # Quantum Modules
    "quantum_threat_intel", "QuantumThreatIntel",
    "quantum_dark_web", "QuantumDarkWebMonitor",
    "quantum_deepfake", "QuantumDeepfakeDetector",
    "quantum_insurance", "QuantumInsurance",
    "quantum_digital_twin", "QuantumDigitalTwin",
    "quantum_blockchain", "QuantumBlockchain",
    "quantum_pentest", "QuantumPentest",
    "quantum_memory_forensics", "QuantumMemoryForensics",
    "quantum_network_analyzer", "QuantumNetworkAnalyzer",
    "quantum_mobile_scanner", "QuantumMobileScanner",
    "quantum_cloud_scanner", "QuantumCloudScanner",
    "quantum_secrets", "QuantumSecretsDetector",
    # Phase 5-10: Advanced Platform Modules
    "AutoSOCOrchestrator",
    "PredictiveAttackEngine",
    "NeuralSecurityMesh",
    "DarkWebIntelNetwork",
    "CyberRiskQuantification",
    "ActiveDefenseCountermeasures",
    "BlockchainTrustNetwork",
    "QuantumSafeSecurity",
    "AutonomousThreatHunterV2",
    "GlobalSOCDashboard",
]
