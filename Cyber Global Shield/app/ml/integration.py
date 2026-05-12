"""
Cyber Global Shield — Ultra Module Integration Hub
====================================================
Connecte et orchestre les 12 niveaux ultra en un pipeline unifié.
"""

import torch
import numpy as np
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
import structlog
import asyncio
from collections import defaultdict

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# RESULT TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class UnifiedDetectionResult:
    """Résultat unifié de tous les niveaux."""
    # Niveau 1: Détection
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    anomaly_confidence: float = 0.0

    # Niveau 2: Prédiction
    prediction_score: float = 0.0
    predicted_attack_type: str = "none"
    prediction_confidence: float = 0.0

    # Niveau 3: Crypto
    crypto_verified: bool = False
    crypto_algorithm: str = "none"

    # Niveau 4: Auto-Remediation
    remediation_action: str = "none"
    remediation_confidence: float = 0.0

    # Niveau 5: Threat Intel
    threat_intel_score: float = 0.0
    known_threats: List[str] = field(default_factory=list)

    # Niveau 6: Zero-Day
    zero_day_score: float = 0.0
    is_zero_day: bool = False

    # Niveau 7: Forensics
    forensics_score: float = 0.0
    forensics_findings: List[str] = field(default_factory=list)

    # Niveau 8: Network
    network_score: float = 0.0
    network_anomalies: List[str] = field(default_factory=list)

    # Niveau 9: Biometrics
    biometrics_score: float = 0.0
    identity_risk: str = "none"

    # Niveau 10: Federated
    federated_score: float = 0.0
    global_model_version: str = "none"

    # Niveau 11: Ensemble
    ensemble_score: float = 0.0
    ensemble_confidence: float = 0.0
    ensemble_uncertainty: float = 0.0

    # Niveau 12: Auto-ML
    auto_ml_config: Dict[str, Any] = field(default_factory=dict)

    # Métadonnées
    inference_time_ms: float = 0.0
    timestamp: str = ""
    model_name: str = "UltraIntegrationHub"


@dataclass
class IntegrationStats:
    """Statistiques d'intégration."""
    total_predictions: int = 0
    anomalies_detected: int = 0
    zero_day_detected: int = 0
    avg_inference_time_ms: float = 0.0
    module_stats: Dict[str, Any] = field(default_factory=dict)
    last_prediction: Optional[UnifiedDetectionResult] = None


# ═══════════════════════════════════════════════════════════════════════════
# ULTRA INTEGRATION HUB
# ═══════════════════════════════════════════════════════════════════════════

class UltraIntegrationHub:
    """
    Hub central qui connecte et orchestre les 12 niveaux ultra.
    """

    def __init__(self, device: str = "cpu"):
        self.device = device
        self.modules: Dict[str, Any] = {}
        self.stats = IntegrationStats()
        self.history: List[UnifiedDetectionResult] = []
        self._initialized = False

        logger.info("ultra_integration_hub_initialized")

    def register_module(self, name: str, module: Any):
        """Register a module."""
        self.modules[name] = module
        logger.info("module_registered", name=name)

    async def initialize_all(self):
        """Initialize all registered modules."""
        for name, module in self.modules.items():
            if hasattr(module, 'initialize'):
                if asyncio.iscoroutinefunction(module.initialize):
                    await module.initialize()
                else:
                    module.initialize()
            logger.info("module_initialized", name=name)
        self._initialized = True
        logger.info("all_modules_initialized", n_modules=len(self.modules))

    async def analyze(
        self,
        data: Dict[str, Any],
        features: Optional[torch.Tensor] = None,
    ) -> UnifiedDetectionResult:
        """
        Analyse unifiée via tous les modules disponibles.
        """
        start_time = datetime.now(timezone.utc)
        result = UnifiedDetectionResult(
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        # Niveau 1: Détection
        if "detector" in self.modules:
            try:
                r = self.modules["detector"].predict(data)
                result.anomaly_score = r.score if hasattr(r, 'score') else 0.0
                result.is_anomaly = r.is_malicious if hasattr(r, 'is_malicious') else False
                result.anomaly_confidence = r.confidence if hasattr(r, 'confidence') else 0.0
            except Exception as e:
                logger.error("detector_error", error=str(e))

        # Niveau 2: Prédiction
        if "predictor" in self.modules:
            try:
                r = self.modules["predictor"].predict(data)
                result.prediction_score = r.score if hasattr(r, 'score') else 0.0
                result.prediction_confidence = r.confidence if hasattr(r, 'confidence') else 0.0
            except Exception as e:
                logger.error("predictor_error", error=str(e))

        # Niveau 3: Crypto
        if "crypto" in self.modules:
            try:
                r = self.modules["crypto"].verify(data)
                result.crypto_verified = r.get('verified', False) if isinstance(r, dict) else False
            except Exception as e:
                logger.error("crypto_error", error=str(e))

        # Niveau 4: Auto-Remediation
        if "remediation" in self.modules:
            try:
                r = self.modules["remediation"].suggest_action(data)
                result.remediation_action = r.get('action', 'none') if isinstance(r, dict) else 'none'
                result.remediation_confidence = r.get('confidence', 0.0) if isinstance(r, dict) else 0.0
            except Exception as e:
                logger.error("remediation_error", error=str(e))

        # Niveau 5: Threat Intel
        if "threat_intel" in self.modules:
            try:
                r = self.modules["threat_intel"].analyze(data)
                result.threat_intel_score = r.score if hasattr(r, 'score') else 0.0
                result.known_threats = r.get('threats', []) if isinstance(r, dict) else []
            except Exception as e:
                logger.error("threat_intel_error", error=str(e))

        # Niveau 6: Zero-Day
        if "zero_day" in self.modules:
            try:
                r = self.modules["zero_day"].detect(data)
                result.zero_day_score = r.score if hasattr(r, 'score') else 0.0
                result.is_zero_day = r.is_malicious if hasattr(r, 'is_malicious') else False
            except Exception as e:
                logger.error("zero_day_error", error=str(e))

        # Niveau 7: Forensics
        if "forensics" in self.modules:
            try:
                r = self.modules["forensics"].analyze(data)
                result.forensics_score = r.score if hasattr(r, 'score') else 0.0
                result.forensics_findings = r.get('findings', []) if isinstance(r, dict) else []
            except Exception as e:
                logger.error("forensics_error", error=str(e))

        # Niveau 8: Network
        if "network" in self.modules:
            try:
                r = self.modules["network"].analyze(data)
                result.network_score = r.score if hasattr(r, 'score') else 0.0
                result.network_anomalies = r.get('anomalies', []) if isinstance(r, dict) else []
            except Exception as e:
                logger.error("network_error", error=str(e))

        # Niveau 9: Biometrics
        if "biometrics" in self.modules:
            try:
                r = self.modules["biometrics"].analyze(data)
                result.biometrics_score = r.score if hasattr(r, 'score') else 0.0
                result.identity_risk = r.get('risk', 'none') if isinstance(r, dict) else 'none'
            except Exception as e:
                logger.error("biometrics_error", error=str(e))

        # Niveau 10: Federated
        if "federated" in self.modules:
            try:
                r = self.modules["federated"].predict(data)
                result.federated_score = r.score if hasattr(r, 'score') else 0.0
            except Exception as e:
                logger.error("federated_error", error=str(e))

        # Niveau 11: Ensemble
        if "ensemble" in self.modules:
            try:
                r = self.modules["ensemble"].predict(data)
                result.ensemble_score = r.score if hasattr(r, 'score') else 0.0
                result.ensemble_confidence = r.confidence if hasattr(r, 'confidence') else 0.0
                result.ensemble_uncertainty = r.uncertainty if hasattr(r, 'uncertainty') else 0.0
            except Exception as e:
                logger.error("ensemble_error", error=str(e))

        # Niveau 12: Auto-ML
        if "auto_ml" in self.modules:
            try:
                config = self.modules["auto_ml"].get_best_config()
                result.auto_ml_config = config if isinstance(config, dict) else {}
            except Exception as e:
                logger.error("auto_ml_error", error=str(e))

        # Calcul du temps d'inférence
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        result.inference_time_ms = elapsed

        # Mise à jour des stats
        self.stats.total_predictions += 1
        if result.is_anomaly:
            self.stats.anomalies_detected += 1
        if result.is_zero_day:
            self.stats.zero_day_detected += 1
        self.stats.avg_inference_time_ms = (
            self.stats.avg_inference_time_ms * (self.stats.total_predictions - 1) + elapsed
        ) / self.stats.total_predictions
        self.stats.last_prediction = result

        self.history.append(result)
        if len(self.history) > 1000:
            self.history.pop(0)

        return result

    def get_stats(self) -> IntegrationStats:
        """Get integration statistics."""
        self.stats.module_stats = {
            name: module.get_stats() if hasattr(module, 'get_stats') else {}
            for name, module in self.modules.items()
        }
        return self.stats

    def get_module(self, name: str) -> Optional[Any]:
        """Get a registered module by name."""
        return self.modules.get(name)


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def create_integration_hub(device: str = "cpu") -> UltraIntegrationHub:
    """Create and configure the integration hub."""
    hub = UltraIntegrationHub(device=device)

    # Try to import and register all ultra modules
    module_imports = [
        ("detector", "app.ml.ultra_detector", "get_ultra_detector"),
        ("predictor", "app.ml.ultra_predictor", "get_ultra_predictor"),
        ("classifier", "app.ml.ultra_classifier", "get_ultra_classifier"),
        ("remediation", "app.ml.ultra_remediation", "get_ultra_remediation"),
        ("crypto", "app.ml.ultra_crypto", "get_ultra_crypto"),
        ("threat_intel", "app.ml.ultra_threat_intel", "get_ultra_threat_intel"),
        ("zero_day", "app.ml.ultra_zero_day", "get_ultra_zero_day"),
        ("forensics", "app.ml.ultra_forensics", "get_ultra_forensics"),
        ("network", "app.ml.ultra_network", "get_ultra_network"),
        ("biometrics", "app.ml.ultra_biometrics", "get_ultra_biometrics"),
        ("federated", "app.ml.ultra_federated", "get_ultra_federated"),
        ("ensemble", "app.ml.meta_ensemble", "get_meta_ensemble"),
        ("auto_ml", "app.ml.auto_optimizer", "get_auto_optimizer"),
    ]

    for name, module_path, func_name in module_imports:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            getter = getattr(mod, func_name, None)
            if getter:
                instance = getter()
                hub.register_module(name, instance)
                logger.info(f"✅ {name} registered successfully")
            else:
                logger.warning(f"⚠️ {func_name} not found in {module_path}")
        except ImportError as e:
            logger.warning(f"⚠️ Could not import {module_path}: {e}")
        except Exception as e:
            logger.warning(f"⚠️ Error registering {name}: {e}")

    return hub


# Instance globale
integration_hub = create_integration_hub()


def get_integration_hub() -> UltraIntegrationHub:
    """Get the global integration hub instance."""
    return integration_hub
