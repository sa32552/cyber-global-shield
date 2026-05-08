"""
Cyber Global Shield — Core Security Modules
Centralized exports for all security modules.
"""

from app.core.config import settings
from app.core.database import get_db, init_db
from app.core.security import create_access_token, verify_token, get_current_user

# Security Modules
from app.core.honeypot import honeypot_intelligence, HoneypotIntelligence
from app.core.ransomware_shield import ransomware_shield, RansomwareShield
from app.core.zero_day_detector import zero_day_detector, ZeroDayDetector
from app.core.supply_chain_security import supply_chain_security, SupplyChainSecurity
from app.core.deep_packet_inspector import deep_packet_inspector, DeepPacketInspector
from app.core.behavioral_biometrics import behavioral_biometrics, BehavioralBiometrics
from app.core.dark_web_monitor import dark_web_monitor, DarkWebMonitor
from app.core.automated_forensics import automated_forensics, AutomatedForensics
from app.core.threat_intel import threat_intel, ThreatIntel
from app.core.ai_deception_grid import ai_deception_grid, AIDeceptionGrid
from app.core.self_healing import self_healing, SelfHealing
from app.core.quantum_crypto import quantum_crypto, QuantumCrypto
from app.core.autonomous_threat_hunter import autonomous_threat_hunter, AutonomousThreatHunter
from app.core.blockchain_audit import blockchain_audit, BlockchainAudit
from app.core.deepfake_detector import deepfake_detector, DeepfakeDetector
from app.core.automated_threat_modeling import automated_threat_modeling, AutomatedThreatModeling
from app.core.zero_trust_microseg import zero_trust_microseg, ZeroTrustMicroseg
from app.core.ai_code_auditor import ai_code_auditor, AICodeAuditor
from app.core.automated_compliance import automated_compliance, AutomatedCompliance
from app.core.predictive_insurance import predictive_insurance, PredictiveInsurance
from app.core.digital_twin_security import digital_twin_security, DigitalTwinSecurity
from app.core.autonomous_pentest import autonomous_pentest, AutonomousPentest
from app.core.memory_forensics import memory_forensics, MemoryForensics
from app.core.network_traffic_analyzer import network_traffic_analyzer, NetworkTrafficAnalyzer
from app.core.mobile_security_scanner import mobile_scanner, MobileSecurityScanner
from app.core.cloud_security_posture import cloud_security_posture, CloudSecurityPosture
from app.core.secrets_detection import secrets_detection, SecretsDetectionEngine
from app.core.security_dashboard_api import security_dashboard_api, SecurityDashboardAPI
from app.core.performance_optimizer import performance_optimizer, PerformanceOptimizer

# Additional modules
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

# Quantum Modules
from app.core.quantum_threat_intel import quantum_threat_intel, QuantumThreatIntel
from app.core.quantum_dark_web import quantum_dark_web, QuantumDarkWebMonitor
from app.core.quantum_deepfake import quantum_deepfake, QuantumDeepfakeDetector
from app.core.quantum_insurance import quantum_insurance, QuantumInsurance
from app.core.quantum_digital_twin import quantum_digital_twin, QuantumDigitalTwin
from app.core.quantum_blockchain import quantum_blockchain, QuantumBlockchain
from app.core.quantum_pentest import quantum_pentest, QuantumPentest
from app.core.quantum_memory_forensics import quantum_memory_forensics, QuantumMemoryForensics
from app.core.quantum_network_analyzer import quantum_network_analyzer, QuantumNetworkAnalyzer
from app.core.quantum_mobile_scanner import quantum_mobile_scanner, QuantumMobileScanner
from app.core.quantum_cloud_security import quantum_cloud_scanner, QuantumCloudScanner
from app.core.quantum_secrets import quantum_secrets, QuantumSecretsDetector

# Phase 5-10: Advanced Platform Modules
from app.core.auto_soc_orchestrator import AutoSOCOrchestrator
from app.core.predictive_attack_engine import PredictiveAttackEngine
from app.core.neural_security_mesh import NeuralSecurityMesh
from app.core.dark_web_intel_network import DarkWebIntelNetwork
from app.core.cyber_risk_quantification import CyberRiskQuantification
from app.core.active_defense_countermeasures import ActiveDefenseCountermeasures
from app.core.blockchain_trust_network import BlockchainTrustNetwork
from app.core.quantum_safe_security import QuantumSafeSecurity
from app.core.autonomous_threat_hunter_v2 import AutonomousThreatHunterV2
from app.core.global_soc_dashboard import GlobalSOCDashboard

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


