"""
Cyber Global Shield — ML Module Exports
========================================
Tous les niveaux 1-12 ultra + modules existants.
"""

# ─── Modules existants ────────────────────────────────────────────────────
from app.ml.anomaly_detector import (
    AnomalyDetector,
    AnomalyDetectionResult,
    TransformerAutoencoder,
    create_default_detector,
)
from app.ml.dataset_generator import NetworkLogGenerator
from app.ml.gnn_detector import (
    GNNAttackDetector,
    GraphFeatureExtractor,
    NetworkNode,
    NetworkEdge,
    AttackPath,
    create_default_gnn_detector,
)
from app.ml.online_detector import OnlineDetector
from app.ml.attack_predictor import AttackPredictor
from app.ml.adversarial_defense import AdversarialDefense
from app.ml.quantum_anomaly_detector import QuantumAnomalyDetector
from app.ml.quantum_kernel import QuantumKernel
from app.ml.quantum_federated import QuantumFederatedServer
from app.ml.quantum_crypto_v2 import QuantumCryptoV2
from app.ml.rl_auto_remediation import RLAutoRemediation
from app.ml.adaptive_honeypot import AdaptiveHoneypot

# ─── Niveau 1: Ultra Detection ────────────────────────────────────────────
from app.ml.ultra_detector import (
    UltraDetector,
    UltraDetectionResult,
    create_ultra_detector,
    get_ultra_detector,
)

# ─── Niveau 2: Ultra Prediction ───────────────────────────────────────────
from app.ml.ultra_predictor import (
    UltraPredictor,
    UltraPredictionResult,
    create_ultra_predictor,
    get_ultra_predictor,
)

# ─── Niveau 3: Ultra Classifier ───────────────────────────────────────────
from app.ml.ultra_classifier import (
    UltraClassifier,
    UltraClassificationResult,
    create_ultra_classifier,
    get_ultra_classifier,
)

# ─── Niveau 4: Ultra Remediation ──────────────────────────────────────────
from app.ml.ultra_remediation import (
    UltraAutoRemediation,
    RemediationAction,
    create_ultra_remediation,
    get_ultra_remediation,
)

# ─── Niveau 5: Ultra Crypto ───────────────────────────────────────────────
from app.ml.ultra_crypto import (
    UltraCrypto,
    UltraCryptoResult,
    create_ultra_crypto,
    get_ultra_crypto,
)

# ─── Niveau 6: Ultra Threat Intel ─────────────────────────────────────────
from app.ml.ultra_threat_intel import (
    UltraThreatIntel,
    ThreatIntelResult,
    create_ultra_threat_intel,
    get_ultra_threat_intel,
)

# ─── Niveau 7: Ultra Zero-Day ─────────────────────────────────────────────
from app.ml.ultra_zero_day import (
    UltraZeroDay,
    ZeroDayResult,
    create_ultra_zero_day,
    get_ultra_zero_day,
)

# ─── Niveau 8: Ultra Forensics ────────────────────────────────────────────
from app.ml.ultra_forensics import (
    UltraForensics,
    ForensicsResult,
    create_ultra_forensics,
    get_ultra_forensics,
)

# ─── Niveau 9: Ultra Network ──────────────────────────────────────────────
from app.ml.ultra_network import (
    UltraNetworkAnalyzer,
    NetworkAnalysisResult,
    create_ultra_network,
    get_ultra_network,
)

# ─── Niveau 10: Ultra Biometrics ──────────────────────────────────────────
from app.ml.ultra_biometrics import (
    UltraBiometrics,
    BiometricsResult,
    create_ultra_biometrics,
    get_ultra_biometrics,
)

# ─── Niveau 11: Meta Ensemble ─────────────────────────────────────────────
from app.ml.meta_ensemble import (
    MetaEnsembleOrchestrator,
    StackingEnsemble,
    BayesianModelAveraging,
    MixtureOfExperts,
    DARTSNetwork,
    OnlineWeightAdapter,
    UncertaintyQuantifier,
    create_meta_ensemble,
    get_meta_ensemble,
)

# ─── Niveau 12: Auto Optimizer ────────────────────────────────────────────
from app.ml.auto_optimizer import (
    AutoMLOrchestrator,
    BayesianOptimizer,
    HyperbandOptimizer,
    PopulationBasedTraining,
    CMAESOptimizer,
    AutoAugmentPolicy,
    SearchSpace,
    create_auto_optimizer,
    get_auto_optimizer,
)

# ─── Integration Hub ──────────────────────────────────────────────────────
from app.ml.integration import (
    UltraIntegrationHub,
    UnifiedDetectionResult,
    IntegrationStats,
    create_integration_hub,
    get_integration_hub,
)

__all__ = [
    # Modules existants
    "AnomalyDetector",
    "AnomalyDetectionResult",
    "TransformerAutoencoder",
    "create_default_detector",
    "NetworkLogGenerator",
    "GNNAttackDetector",
    "GraphFeatureExtractor",
    "NetworkNode",
    "NetworkEdge",
    "AttackPath",
    "create_default_gnn_detector",
    "OnlineDetector",
    "AttackPredictor",
    "AdversarialDefense",
    "QuantumAnomalyDetector",
    "QuantumKernel",
    "QuantumFederatedServer",
    "QuantumCryptoV2",
    "RLAutoRemediation",
    "AdaptiveHoneypot",

    # Niveau 1
    "UltraDetector",
    "UltraDetectionResult",
    "create_ultra_detector",
    "get_ultra_detector",

    # Niveau 2
    "UltraPredictor",
    "UltraPredictionResult",
    "create_ultra_predictor",
    "get_ultra_predictor",

    # Niveau 3
    "UltraClassifier",
    "UltraClassificationResult",
    "create_ultra_classifier",
    "get_ultra_classifier",

    # Niveau 4
    "UltraAutoRemediation",
    "RemediationAction",
    "create_ultra_remediation",
    "get_ultra_remediation",

    # Niveau 5
    "UltraCrypto",
    "UltraCryptoResult",
    "create_ultra_crypto",
    "get_ultra_crypto",

    # Niveau 6
    "UltraThreatIntel",
    "ThreatIntelResult",
    "create_ultra_threat_intel",
    "get_ultra_threat_intel",

    # Niveau 7
    "UltraZeroDay",
    "ZeroDayResult",
    "create_ultra_zero_day",
    "get_ultra_zero_day",

    # Niveau 8
    "UltraForensics",
    "ForensicsResult",
    "create_ultra_forensics",
    "get_ultra_forensics",

    # Niveau 9
    "UltraNetworkAnalyzer",
    "NetworkAnalysisResult",
    "create_ultra_network",
    "get_ultra_network",

    # Niveau 10
    "UltraBiometrics",
    "BiometricsResult",
    "create_ultra_biometrics",
    "get_ultra_biometrics",

    # Niveau 11
    "MetaEnsembleOrchestrator",
    "StackingEnsemble",
    "BayesianModelAveraging",
    "MixtureOfExperts",
    "DARTSNetwork",
    "OnlineWeightAdapter",
    "UncertaintyQuantifier",
    "create_meta_ensemble",
    "get_meta_ensemble",

    # Niveau 12
    "AutoMLOrchestrator",
    "BayesianOptimizer",
    "HyperbandOptimizer",
    "PopulationBasedTraining",
    "CMAESOptimizer",
    "AutoAugmentPolicy",
    "SearchSpace",
    "create_auto_optimizer",
    "get_auto_optimizer",

    # Integration Hub
    "UltraIntegrationHub",
    "UnifiedDetectionResult",
    "IntegrationStats",
    "create_integration_hub",
    "get_integration_hub",
]
