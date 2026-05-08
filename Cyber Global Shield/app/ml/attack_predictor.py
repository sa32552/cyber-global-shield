"""
Cyber Global Shield — AI-Powered Attack Prevention
Prédit les attaques avant qu'elles ne se produisent en utilisant le ML,
l'analyse de corrélation et le Threat Intelligence Scoring.
"""

import json
import logging
import hashlib
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class AttackPrediction:
    """A predicted attack."""
    timestamp: datetime
    attack_type: str  # ransomware, phishing, ddos, apt, data_breach, insider
    probability: float  # 0.0 to 1.0
    severity: str  # low, medium, high, critical
    target: str  # IP, service, user, system
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    time_to_attack: Optional[int] = None  # minutes
    mitre_technique: Optional[str] = None
    confidence: float = 0.0


@dataclass
class ThreatSignal:
    """A threat signal used for prediction."""
    timestamp: datetime
    signal_type: str  # scan, brute_force, anomaly, ioc, behavioral
    source: str
    target: str
    severity: float
    details: Dict[str, Any] = field(default_factory=dict)


class AttackPredictor:
    """
    Prédicteur d'attaques basé sur l'IA.
    
    Utilise:
    - Corrélation de signaux faibles
    - Analyse de séquence temporelle
    - Scoring de menace contextuel
    - MITRE ATT&CK mapping
    - Prédiction de la prochaine étape (next move prediction)
    """

    def __init__(self):
        self._signals: List[ThreatSignal] = []
        self._predictions: List[AttackPrediction] = []
        self._attack_patterns = self._load_attack_patterns()
        self._max_signal_age = timedelta(hours=24)

    def _load_attack_patterns(self) -> Dict[str, List[Dict]]:
        """Load known attack patterns for prediction."""
        return {
            "ransomware": {
                "precursors": [
                    {"type": "scan", "weight": 0.3},
                    {"type": "brute_force", "weight": 0.2},
                    {"type": "phishing", "weight": 0.5},
                ],
                "time_window": 48,  # hours
                "mitre_technique": "T1486",
                "actions": [
                    "Activer le Ransomware Shield",
                    "Isoler les systèmes critiques",
                    "Déclencher les backups d'urgence",
                    "Bloquer les extensions exécutables",
                ],
            },
            "apt": {
                "precursors": [
                    {"type": "phishing", "weight": 0.4},
                    {"type": "ioc", "weight": 0.3},
                    {"type": "behavioral", "weight": 0.3},
                ],
                "time_window": 168,  # 7 days
                "mitre_technique": "T1078",
                "actions": [
                    "Activer la surveillance renforcée",
                    "Analyser les connexions sortantes",
                    "Vérifier les comptes privilégiés",
                    "Scanner la mémoire des endpoints",
                ],
            },
            "ddos": {
                "precursors": [
                    {"type": "scan", "weight": 0.6},
                    {"type": "anomaly", "weight": 0.4},
                ],
                "time_window": 24,
                "mitre_technique": "T1498",
                "actions": [
                    "Activer le rate limiting",
                    "Déployer les règles WAF",
                    "Augmenter la capacité réseau",
                    "Activer Cloudflare/CloudFront",
                ],
            },
            "data_breach": {
                "precursors": [
                    {"type": "behavioral", "weight": 0.3},
                    {"type": "anomaly", "weight": 0.3},
                    {"type": "ioc", "weight": 0.4},
                ],
                "time_window": 72,
                "mitre_technique": "T1530",
                "actions": [
                    "Restreindre l'accès aux données",
                    "Activer le DLP",
                    "Auditer les permissions",
                    "Déclencher l'alerte breach",
                ],
            },
            "insider_threat": {
                "precursors": [
                    {"type": "behavioral", "weight": 0.5},
                    {"type": "anomaly", "weight": 0.5},
                ],
                "time_window": 168,
                "mitre_technique": "T1078.004",
                "actions": [
                    "Restreindre les accès",
                    "Activer l'enregistrement des sessions",
                    "Analyser les téléchargements",
                    "Révoquer les accès sensibles",
                ],
            },
        }

    def add_signal(self, signal: ThreatSignal):
        """Add a threat signal for analysis."""
        self._signals.append(signal)
        
        # Clean old signals
        cutoff = datetime.utcnow() - self._max_signal_age
        self._signals = [s for s in self._signals if s.timestamp > cutoff]

        # Run prediction
        prediction = self._predict_attack()
        if prediction:
            self._predictions.append(prediction)
            logger.warning(
                f"🔮 Attack predicted: {prediction.attack_type} "
                f"(prob: {prediction.probability:.2f}, "
                f"target: {prediction.target})"
            )

    def _predict_attack(self) -> Optional[AttackPrediction]:
        """Predict the next likely attack based on signals."""
        now = datetime.utcnow()
        best_prediction = None
        best_score = 0.0

        for attack_type, pattern in self._attack_patterns.items():
            score = 0.0
            matched_indicators = []
            time_window = timedelta(hours=pattern["time_window"])

            # Check each precursor signal
            for precursor in pattern["precursors"]:
                matching_signals = [
                    s for s in self._signals
                    if s.signal_type == precursor["type"]
                    and (now - s.timestamp) < time_window
                ]
                
                if matching_signals:
                    # Weight by recency and severity
                    for signal in matching_signals:
                        recency_weight = 1.0 - (
                            (now - signal.timestamp).total_seconds() 
                            / time_window.total_seconds()
                        )
                        score += (
                            precursor["weight"] 
                            * signal.severity 
                            * recency_weight
                        )
                        matched_indicators.append(
                            f"{signal.signal_type}: {signal.source} -> {signal.target}"
                        )

            # Normalize score
            if matched_indicators:
                score = min(score / len(matched_indicators), 1.0)

            if score > best_score and score > 0.3:
                best_score = score
                best_prediction = AttackPrediction(
                    timestamp=now,
                    attack_type=attack_type,
                    probability=score,
                    severity="critical" if score > 0.7 else "high" if score > 0.5 else "medium",
                    target=self._predict_target(attack_type),
                    indicators=matched_indicators[:5],
                    recommended_actions=pattern["actions"],
                    time_to_attack=self._estimate_time_to_attack(attack_type),
                    mitre_technique=pattern["mitre_technique"],
                    confidence=score,
                )

        return best_prediction

    def _predict_target(self, attack_type: str) -> str:
        """Predict the most likely target based on signals."""
        # Find most targeted entity
        targets = defaultdict(int)
        for signal in self._signals:
            if signal.severity > 0.5:
                targets[signal.target] += signal.severity

        if targets:
            return max(targets.items(), key=lambda x: x[1])[0]
        return "unknown"

    def _estimate_time_to_attack(self, attack_type: str) -> int:
        """Estimate minutes until predicted attack."""
        pattern = self._attack_patterns.get(attack_type, {})
        time_window = pattern.get("time_window", 48)
        
        # More signals = sooner attack
        recent_signals = [
            s for s in self._signals
            if s.signal_type in [p["type"] for p in pattern.get("precursors", [])]
        ]
        
        if len(recent_signals) > 10:
            return int(time_window * 0.25 * 60)  # 25% of window
        elif len(recent_signals) > 5:
            return int(time_window * 0.5 * 60)   # 50% of window
        else:
            return int(time_window * 0.75 * 60)  # 75% of window

    def get_active_predictions(self) -> List[AttackPrediction]:
        """Get active (not expired) predictions."""
        now = datetime.utcnow()
        return [
            p for p in self._predictions
            if p.time_to_attack is None
            or (now - p.timestamp).total_seconds() < p.time_to_attack * 60
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get attack predictor statistics."""
        active = self.get_active_predictions()
        return {
            "total_predictions": len(self._predictions),
            "active_predictions": len(active),
            "critical_predictions": len([p for p in active if p.severity == "critical"]),
            "high_predictions": len([p for p in active if p.severity == "high"]),
            "attack_types": list(set(p.attack_type for p in active)),
            "avg_probability": (
                sum(p.probability for p in active) / len(active)
                if active else 0.0
            ),
            "signals_analyzed": len(self._signals),
            "status": "PREDICTING" if active else "MONITORING",
        }


attack_predictor = AttackPredictor()
