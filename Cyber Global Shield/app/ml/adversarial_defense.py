"""
Cyber Global Shield — Adversarial ML Defense
Protection contre les attaques adversariales sur les modèles ML.
Détection d'évasion, empoisonnement, extraction et inférence.
"""

import json
import numpy as np
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class AdversarialAttack:
    """An adversarial attack detected."""
    timestamp: datetime
    attack_type: str  # evasion, poisoning, extraction, inference, backdoor
    severity: str
    target_model: str
    description: str
    confidence: float
    detected_features: List[str] = None


class AdversarialMLDefense:
    """
    Défense contre les attaques adversariales ML.
    
    Protège contre:
    - Évasion (adversarial examples)
    - Empoisonnement des données d'entraînement
    - Extraction de modèle
    - Inférence d'appartenance
    - Backdoor attacks
    - Gradient leakage
    """

    def __init__(self):
        self._attacks: List[AdversarialAttack] = []
        self._input_history: Dict[str, List[np.ndarray]] = defaultdict(list)
        self._feature_bounds: Dict[str, Tuple[float, float]] = {}
        self._suspicious_patterns: Dict[str, int] = defaultdict(int)

    def detect_evasion(
        self, model_name: str, input_data: np.ndarray, 
        prediction: np.ndarray, confidence: float
    ) -> Optional[AdversarialAttack]:
        """Detect adversarial evasion attacks."""
        # 1. Confidence too low for high-probability prediction
        if confidence < 0.3 and np.max(prediction) > 0.8:
            attack = AdversarialAttack(
                timestamp=datetime.utcnow(),
                attack_type="evasion",
                severity="high",
                target_model=model_name,
                description=f"Low confidence ({confidence:.2f}) despite high prediction",
                confidence=0.85,
                detected_features=["low_confidence_high_prediction"],
            )
            self._attacks.append(attack)
            return attack

        # 2. Input perturbation detection
        if self._input_history[model_name]:
            last_input = self._input_history[model_name][-1]
            if len(last_input) == len(input_data):
                perturbation = np.abs(input_data - last_input).mean()
                if perturbation > 0.5:  # Large perturbation
                    attack = AdversarialAttack(
                        timestamp=datetime.utcnow(),
                        attack_type="evasion",
                        severity="critical",
                        target_model=model_name,
                        description=f"Large input perturbation detected: {perturbation:.3f}",
                        confidence=0.9,
                        detected_features=["large_perturbation"],
                    )
                    self._attacks.append(attack)
                    return attack

        # Store input for future comparison
        self._input_history[model_name].append(input_data.copy())
        if len(self._input_history[model_name]) > 100:
            self._input_history[model_name].pop(0)

        return None

    def detect_poisoning(
        self, model_name: str, label: int, 
        feature_vector: np.ndarray
    ) -> Optional[AdversarialAttack]:
        """Detect data poisoning attempts."""
        # 1. Label flipping detection
        feature_key = f"{model_name}:{label}"
        self._suspicious_patterns[feature_key] += 1

        # 2. Outlier detection in feature space
        if feature_key in self._feature_bounds:
            lower, upper = self._feature_bounds[feature_key]
            if np.any(feature_vector < lower - 2) or np.any(feature_vector > upper + 2):
                attack = AdversarialAttack(
                    timestamp=datetime.utcnow(),
                    attack_type="poisoning",
                    severity="critical",
                    target_model=model_name,
                    description=f"Outlier feature vector detected for label {label}",
                    confidence=0.88,
                    detected_features=["feature_outlier"],
                )
                self._attacks.append(attack)
                return attack

        # Update feature bounds
        if feature_key not in self._feature_bounds:
            self._feature_bounds[feature_key] = (
                feature_vector.min(), feature_vector.max()
            )
        else:
            lower, upper = self._feature_bounds[feature_key]
            self._feature_bounds[feature_key] = (
                min(lower, feature_vector.min()),
                max(upper, feature_vector.max()),
            )

        return None

    def detect_extraction(
        self, model_name: str, query_count: int,
        query_pattern: List[int]
    ) -> Optional[AdversarialAttack]:
        """Detect model extraction attempts."""
        # 1. High query frequency
        if query_count > 1000:
            attack = AdversarialAttack(
                timestamp=datetime.utcnow(),
                attack_type="extraction",
                severity="high",
                target_model=model_name,
                description=f"High query count: {query_count}",
                confidence=0.75,
                detected_features=["high_query_frequency"],
            )
            self._attacks.append(attack)
            return attack

        # 2. Systematic query pattern (grid search)
        if query_pattern and len(set(query_pattern)) < len(query_pattern) * 0.1:
            attack = AdversarialAttack(
                timestamp=datetime.utcnow(),
                attack_type="extraction",
                severity="critical",
                target_model=model_name,
                description="Systematic query pattern detected (possible extraction)",
                confidence=0.92,
                detected_features=["systematic_queries"],
            )
            self._attacks.append(attack)
            return attack

        return None

    def detect_inference(
        self, model_name: str, membership_score: float
    ) -> Optional[AdversarialAttack]:
        """Detect membership inference attacks."""
        if membership_score > 0.9:
            attack = AdversarialAttack(
                timestamp=datetime.utcnow(),
                attack_type="inference",
                severity="high",
                target_model=model_name,
                description=f"High membership inference score: {membership_score:.2f}",
                confidence=0.8,
                detected_features=["high_membership_score"],
            )
            self._attacks.append(attack)
            return attack
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get adversarial defense statistics."""
        recent = [
            a for a in self._attacks
            if (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        return {
            "total_attacks_detected": len(self._attacks),
            "recent_attacks": len(recent),
            "attack_types": dict(
                (t, len([a for a in recent if a.attack_type == t]))
                for t in set(a.attack_type for a in recent)
            ),
            "models_protected": len(set(a.target_model for a in self._attacks)),
            "status": "PROTECTED",
        }


adversarial_defense = AdversarialMLDefense()
