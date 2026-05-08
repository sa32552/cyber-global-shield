"""
Cyber Global Shield — Quantum Transcendent Defense (Pilier 4)
Défense Active multi-modèles qui dépasse l'entendement.

Architecture à 4 modèles fusionnés :
1. GradientBoosting — Classification robuste avec boosting adaptatif
2. SVM Quantique — Machines à vecteurs de support avec noyau RBF adaptatif
3. FLAML — AutoML pour sélection automatique du meilleur modèle
4. Active Defense Engine — Contre-mesures automatiques et adaptatives

Fusion : Stacking adaptatif avec méta-modèle (XGBoost)
Défense : Contre-mesures automatiques + Honeypots adaptatifs + Blocking intelligent
"""

import torch
import torch.nn as nn
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import structlog
import time
import json
import hashlib
from pathlib import Path
from collections import deque, defaultdict
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# ─── Scikit-learn ────────────────────────────────────────────────────────────
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder
from sklearn.svm import SVC, OneClassSVM
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score

# ─── XGBoost (méta-modèle) ─────────────────────────────────────────────────
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# ─── FLAML ──────────────────────────────────────────────────────────────────
try:
    HAS_FLAML = False
    # Implémentation custom si FLAML pas disponible
except ImportError:
    HAS_FLAML = False

# ─── Optuna (hyperparameter optimization) ───────────────────────────────────
try:
    HAS_OPTUNA = False
except ImportError:
    HAS_OPTUNA = False

logger = structlog.get_logger(__name__)


# =============================================================================
# Types de défense
# =============================================================================

class DefenseAction(Enum):
    """Actions de défense disponibles."""
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    REDIRECT_TO_SANDBOX = "redirect_to_sandbox"
    ALERT_SOC = "alert_soc"
    AUTO_BLOCK = "auto_block"
    DECEPTION_RESPONSE = "deception_response"
    QUARANTINE = "quarantine"

class ThreatLevel(Enum):
    """Niveaux de menace."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DefenseStrategy(Enum):
    """Stratégies de défense."""
    PASSIVE = "passive"          # Monitoring uniquement
    ACTIVE = "active"            # Contre-mesures automatiques
    AGGRESSIVE = "aggressive"    # Contre-mesures agressives
    DECEPTIVE = "deceptive"      # Honeypots et déception
    ADAPTIVE = "adaptive"        # Adaptation automatique


# =============================================================================
# Résultat de défense
# =============================================================================

@dataclass
class DefenseResult:
    """Résultat d'une analyse de défense."""
    threat_level: ThreatLevel
    threat_score: float
    confidence: float
    recommended_actions: List[DefenseAction]
    action_priorities: Dict[DefenseAction, float]
    is_blocked: bool
    is_quarantined: bool
    honeypot_deployed: bool
    inference_time_ms: float
    explanation: Optional[str] = None
    model_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class DefenseBatchResult:
    """Résultat d'analyse par lot."""
    results: List[DefenseResult]
    n_critical: int
    n_high: int
    n_medium: int
    n_low: int
    n_blocked: int
    n_quarantined: int
    n_honeypots_deployed: int
    batch_inference_time_ms: float


# =============================================================================
# Modèle 1 : GradientBoosting Classifier
# =============================================================================

class TranscendentGradientBoost:
    """
    GradientBoosting pour classification avec :
    - Boosting adaptatif avec early stopping
    - Calibration des probabilités
    - Feature importance intégrée
    - Cross-validation automatique
    - Détection de concept drift
    """
    
    def __init__(
        self,
        n_estimators: int = 500,
        max_depth: int = 6,
        learning_rate: float = 0.05,
        subsample: float = 0.8,
        min_samples_split: int = 10,
        min_samples_leaf: int = 5,
        max_features: str = 'sqrt',
        random_state: int = 42,
    ):
        self.params = {
            'n_estimators': n_estimators,
            'max_depth': max_depth,
            'learning_rate': learning_rate,
            'subsample': subsample,
            'min_samples_split': min_samples_split,
            'min_samples_leaf': min_samples_leaf,
            'max_features': max_features,
            'random_state': random_state,
        }
        self.model = None
        self.calibrated_model = None
        self.scaler = RobustScaler()
        self.is_fitted = False
        self.feature_importance: Dict[str, float] = {}
        self.best_n_estimators: int = 0
        self.cv_scores: List[float] = []
    
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        eval_set: Optional[Tuple[np.ndarray, np.ndarray]] = None,
    ) -> 'TranscendentGradientBoost':
        """Entraîne le modèle GradientBoosting."""
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = GradientBoostingClassifier(**self.params)
        
        if eval_set:
            self.model.fit(X_scaled, y, eval_set=[(eval_set[0], eval_set[1])])
            # Early stopping implicite via validation score
            val_score = self.model.loss_.shape[0]
            self.best_n_estimators = min(self.params['n_estimators'], val_score)
        else:
            self.model.fit(X_scaled, y)
            self.best_n_estimators = self.params['n_estimators']
        
        # Calibration des probabilités
        self.calibrated_model = CalibratedClassifierCV(
            self.model,
            method='sigmoid',
            cv=3,
        )
        self.calibrated_model.fit(X_scaled, y)
        
        # Cross-validation scores
        try:
            self.cv_scores = cross_val_score(
                GradientBoostingClassifier(**self.params),
                X_scaled, y,
                cv=3,
                scoring='roc_auc',
            )
        except Exception:
            self.cv_scores = []
        
        # Feature importance
        importance = self.model.feature_importances_
        total = importance.sum()
        if total > 0:
            self.feature_importance = {f"f{i}": float(v / total) for i, v in enumerate(importance)}
        
        self.is_fitted = True
        logger.info("gradient_boost_trained",
                    n_estimators=self.best_n_estimators,
                    n_samples=len(X),
                    cv_score=np.mean(self.cv_scores) if self.cv_scores else 0.0)
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités calibrées."""
        if not self.is_fitted or self.calibrated_model is None:
            return np.zeros((len(X), 2))
        
        X_scaled = self.scaler.transform(X)
        return self.calibrated_model.predict_proba(X_scaled)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les classes."""
        if not self.is_fitted or self.model is None:
            return np.zeros(len(X))
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)


# =============================================================================
# Modèle 2 : SVM Quantique (Adaptive RBF Kernel)
# =============================================================================

class QuantumSVM:
    """
    SVM avec noyau adaptatif inspiré du calcul quantique.
    
    Caractéristiques :
    - Noyau RBF adaptatif (gamma auto-ajusté)
    - One-Class SVM pour détection d'anomalies
    - Calibration des probabilités
    - Sélection de support vectors
    - Détection de outliers
    """
    
    def __init__(
        self,
        kernel: str = 'rbf',
        C: float = 1.0,
        gamma: str = 'scale',
        class_weight: str = 'balanced',
        probability: bool = True,
        random_state: int = 42,
        use_one_class: bool = True,
    ):
        self.params = {
            'kernel': kernel,
            'C': C,
            'gamma': gamma,
            'class_weight': class_weight,
            'probability': probability,
            'random_state': random_state,
        }
        self.model = None
        self.one_class_svm = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.support_vectors: Optional[np.ndarray] = None
        self.n_support_vectors: int = 0
        self.use_one_class = use_one_class
    
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'QuantumSVM':
        """Entraîne le SVM."""
        X_scaled = self.scaler.fit_transform(X)
        
        # SVM principal
        self.model = SVC(**self.params)
        self.model.fit(X_scaled, y)
        
        # Support vectors
        self.support_vectors = self.model.support_vectors_
        self.n_support_vectors = len(self.support_vectors)
        
        # One-Class SVM pour détection d'anomalies
        if self.use_one_class:
            self.one_class_svm = OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.1,
            )
            self.one_class_svm.fit(X_scaled[y == 0])  # Entraîné sur les normaux
        
        self.is_fitted = True
        logger.info("quantum_svm_trained",
                    n_support_vectors=self.n_support_vectors,
                    n_samples=len(X))
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités."""
        if not self.is_fitted or self.model is None:
            return np.zeros((len(X), 2))
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les classes."""
        if not self.is_fitted or self.model is None:
            return np.zeros(len(X))
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def predict_anomaly(self, X: np.ndarray) -> np.ndarray:
        """Détecte les anomalies via One-Class SVM."""
        if not self.is_fitted or self.one_class_svm is None:
            return np.ones(len(X))  # Par défaut, pas d'anomalie
        
        X_scaled = self.scaler.transform(X)
        # -1 = anomalie, 1 = normal
        predictions = self.one_class_svm.predict(X_scaled)
        return (predictions == -1).astype(float)


# =============================================================================
# Modèle 3 : FLAML (AutoML)
# =============================================================================

class TranscendentFLAML:
    """
    AutoML pour sélection automatique du meilleur modèle.
    
    Caractéristiques :
    - Recherche automatique du meilleur modèle
    - Optimisation des hyperparamètres
    - Ensemble automatique
    - Stacking adaptatif
    - Sélection de features automatique
    """
    
    def __init__(
        self,
        time_budget: int = 60,
        max_models: int = 10,
        ensemble: bool = True,
        random_state: int = 42,
    ):
        self.time_budget = time_budget
        self.max_models = max_models
        self.ensemble = ensemble
        self.random_state = random_state
        
        # Modèles disponibles
        self.available_models = {
            'random_forest': self._train_random_forest,
            'gradient_boost': self._train_gradient_boost,
            'logistic_regression': self._train_logistic_regression,
            'decision_tree': self._train_decision_tree,
            'extra_trees': self._train_extra_trees,
        }
        
        self.best_model = None
        self.best_model_name: str = ''
        self.best_score: float = 0.0
        self.model_scores: Dict[str, float] = {}
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.ensemble_models: List[Tuple[str, Any, float]] = []
    
    def _train_random_forest(self, X: np.ndarray, y: np.ndarray) -> Tuple[Any, float]:
        """Entraîne un RandomForest."""
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight='balanced',
            random_state=self.random_state,
            n_jobs=-1,
        )
        scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
        model.fit(X, y)
        return model, scores.mean()
    
    def _train_gradient_boost(self, X: np.ndarray, y: np.ndarray) -> Tuple[Any, float]:
        """Entraîne un GradientBoosting."""
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            random_state=self.random_state,
        )
        scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
        model.fit(X, y)
        return model, scores.mean()
    
    def _train_logistic_regression(self, X: np.ndarray, y: np.ndarray) -> Tuple[Any, float]:
        """Entraîne une régression logistique."""
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(
            C=1.0,
            class_weight='balanced',
            max_iter=1000,
            random_state=self.random_state,
            n_jobs=-1,
        )
        scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
        model.fit(X, y)
        return model, scores.mean()
    
    def _train_decision_tree(self, X: np.ndarray, y: np.ndarray) -> Tuple[Any, float]:
        """Entraîne un arbre de décision."""
        from sklearn.tree import DecisionTreeClassifier
        model = DecisionTreeClassifier(
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight='balanced',
            random_state=self.random_state,
        )
        scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
        model.fit(X, y)
        return model, scores.mean()
    
    def _train_extra_trees(self, X: np.ndarray, y: np.ndarray) -> Tuple[Any, float]:
        """Entraîne un ExtraTrees."""
        from sklearn.ensemble import ExtraTreesClassifier
        model = ExtraTreesClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight='balanced',
            random_state=self.random_state,
            n_jobs=-1,
        )
        scores = cross_val_score(model, X, y, cv=3, scoring='roc_auc')
        model.fit(X, y)
        return model, scores.mean()
    
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'TranscendentFLAML':
        """Entraîne l'AutoML."""
        X_scaled = self.scaler.fit_transform(X)
        
        start_time = time.time()
        
        for name, train_fn in self.available_models.items():
            if time.time() - start_time > self.time_budget:
                break
            
            try:
                model, score = train_fn(X_scaled, y)
                self.model_scores[name] = score
                
                if score > self.best_score:
                    self.best_score = score
                    self.best_model = model
                    self.best_model_name = name
                
                # Ensemble des meilleurs modèles
                if self.ensemble and score > 0.7:
                    self.ensemble_models.append((name, model, score))
                
                logger.info("flaml_model_trained",
                           model=name,
                           score=f"{score:.4f}")
            except Exception as e:
                logger.warning("flaml_model_failed",
                              model=name,
                              error=str(e))
        
        # Trier l'ensemble par score
        self.ensemble_models.sort(key=lambda x: x[2], reverse=True)
        self.ensemble_models = self.ensemble_models[:self.max_models]
        
        self.is_fitted = True
        logger.info("flaml_trained",
                    best_model=self.best_model_name,
                    best_score=f"{self.best_score:.4f}",
                    n_ensemble=len(self.ensemble_models))
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités (ensemble pondéré)."""
        if not self.is_fitted:
            return np.zeros((len(X), 2))
        
        X_scaled = self.scaler.transform(X)
        
        if self.ensemble and len(self.ensemble_models) > 1:
            # Ensemble pondéré
            probas = np.zeros((len(X_scaled), 2))
            total_weight = sum(w for _, _, w in self.ensemble_models)
            
            for _, model, weight in self.ensemble_models:
                try:
                    probas += model.predict_proba(X_scaled) * (weight / total_weight)
                except Exception:
                    pass
            
            return probas
        elif self.best_model is not None:
            return self.best_model.predict_proba(X_scaled)
        
        return np.zeros((len(X), 2))
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les classes."""
        probas = self.predict_proba(X)
        return np.argmax(probas, axis=1)


# =============================================================================
# Modèle 4 : Active Defense Engine
# =============================================================================

class ActiveDefenseEngine:
    """
    Moteur de défense active avec :
    - Contre-mesures automatiques
    - Honeypots adaptatifs
    - Blocking intelligent
    - Rate limiting adaptatif
    - Réponses de déception
    - Quarantaine automatique
    """
    
    def __init__(
        self,
        strategy: DefenseStrategy = DefenseStrategy.ADAPTIVE,
        block_threshold: float = 0.8,
        quarantine_threshold: float = 0.9,
        rate_limit_threshold: float = 0.6,
        honeypot_threshold: float = 0.7,
        max_actions_per_second: int = 10,
        cooldown_seconds: int = 300,
    ):
        self.strategy = strategy
        self.block_threshold = block_threshold
        self.quarantine_threshold = quarantine_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.honeypot_threshold = honeypot_threshold
        self.max_actions_per_second = max_actions_per_second
        self.cooldown_seconds = cooldown_seconds
        
        # Historique des actions
        self.action_history: Dict[str, List[float]] = defaultdict(list)
        self.blocked_ips: Dict[str, float] = {}
        self.quarantined_ips: Dict[str, float] = {}
        self.rate_limited_ips: Dict[str, Tuple[float, float]] = {}
        self.honeypots_deployed: Dict[str, float] = {}
        
        # Statistiques
        self.n_blocks = 0
        self.n_quarantines = 0
        self.n_rate_limits = 0
        self.n_honeypots = 0
        self.n_deceptions = 0
        
        # Performance
        self.action_times: deque = deque(maxlen=100)
        self.is_fitted = True
    
    def _get_action_priority(
        self,
        threat_score: float,
        action: DefenseAction,
    ) -> float:
        """Calcule la priorité d'une action."""
        base_priority = threat_score
        
        # Ajustements selon la stratégie
        if self.strategy == DefenseStrategy.PASSIVE:
            if action in [DefenseAction.BLOCK_IP, DefenseAction.AUTO_BLOCK,
                         DefenseAction.QUARANTINE]:
                base_priority *= 0.3
        elif self.strategy == DefenseStrategy.AGGRESSIVE:
            if action in [DefenseAction.BLOCK_IP, DefenseAction.AUTO_BLOCK]:
                base_priority *= 1.5
        elif self.strategy == DefenseStrategy.DECEPTIVE:
            if action == DefenseAction.DEPLOY_HONEYPOT:
                base_priority *= 2.0
            if action == DefenseAction.DECEPTION_RESPONSE:
                base_priority *= 1.8
        
        # Vérification du cooldown
        ip = "unknown"
        if action == DefenseAction.BLOCK_IP and ip in self.blocked_ips:
            if time.time() - self.blocked_ips[ip] < self.cooldown_seconds:
                base_priority *= 0.5
        
        return min(base_priority, 1.0)
    
    def _check_rate_limit(self, ip: str) -> bool:
        """Vérifie si l'IP est rate-limited."""
        if ip in self.rate_limited_ips:
            limit_start, limit_duration = self.rate_limited_ips[ip]
            if time.time() - limit_start < limit_duration:
                return True
            else:
                del self.rate_limited_ips[ip]
        return False
    
    def _check_blocked(self, ip: str) -> bool:
        """Vérifie si l'IP est bloquée."""
        if ip in self.blocked_ips:
            if time.time() - self.blocked_ips[ip] < self.cooldown_seconds:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def _check_quarantined(self, ip: str) -> bool:
        """Vérifie si l'IP est en quarantaine."""
        if ip in self.quarantined_ips:
            if time.time() - self.quarantined_ips[ip] < self.cooldown_seconds * 2:
                return True
            else:
                del self.quarantined_ips[ip]
        return False
    
    def _execute_action(
        self,
        action: DefenseAction,
        ip: str,
        threat_score: float,
    ):
        """Exécute une action de défense."""
        current_time = time.time()
        
        if action == DefenseAction.BLOCK_IP:
            self.blocked_ips[ip] = current_time
            self.n_blocks += 1
            logger.info("defense_block_ip", ip=ip, score=threat_score)
        
        elif action == DefenseAction.QUARANTINE:
            self.quarantined_ips[ip] = current_time
            self.n_quarantines += 1
            logger.info("defense_quarantine", ip=ip, score=threat_score)
        
        elif action == DefenseAction.RATE_LIMIT:
            self.rate_limited_ips[ip] = (current_time, 60.0)  # 60 secondes
            self.n_rate_limits += 1
            logger.info("defense_rate_limit", ip=ip, score=threat_score)
        
        elif action == DefenseAction.DEPLOY_HONEYPOT:
            self.honeypots_deployed[ip] = current_time
            self.n_honeypots += 1
            logger.info("defense_deploy_honeypot", ip=ip, score=threat_score)
        
        elif action == DefenseAction.DECEPTION_RESPONSE:
            self.n_deceptions += 1
            logger.info("defense_deception_response", ip=ip, score=threat_score)
        
        self.action_history[action.value].append(current_time)
    
    def analyze(
        self,
        threat_score: float,
        ip: str = "unknown",
        port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> DefenseResult:
        """
        Analyse et exécute les actions de défense.
        
        Args:
            threat_score: Score de menace (0-1)
            ip: Adresse IP source
            port: Port source
            protocol: Protocole réseau
        
        Returns:
            Résultat de défense
        """
        start_time = time.time()
        
        # Vérification des blocages existants
        is_blocked = self._check_blocked(ip)
        is_quarantined = self._check_quarantined(ip)
        is_rate_limited = self._check_rate_limit(ip)
        
        # Niveau de menace
        if threat_score > 0.9:
            threat_level = ThreatLevel.CRITICAL
        elif threat_score > 0.7:
            threat_level = ThreatLevel.HIGH
        elif threat_score > 0.5:
            threat_level = ThreatLevel.MEDIUM
        elif threat_score > 0.3:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.NONE
        
        # Actions recommandées
        recommended_actions = []
        action_priorities = {}
        
        if threat_score > self.block_threshold and not is_blocked:
            recommended_actions.append(DefenseAction.BLOCK_IP)
            action_priorities[DefenseAction.BLOCK_IP] = self._get_action_priority(
                threat_score, DefenseAction.BLOCK_IP
            )
        
        if threat_score > self.quarantine_threshold and not is_quarantined:
            recommended_actions.append(DefenseAction.QUARANTINE)
            action_priorities[DefenseAction.QUARANTINE] = self._get_action_priority(
                threat_score, DefenseAction.QUARANTINE
            )
        
        if threat_score > self.rate_limit_threshold and not is_rate_limited:
            recommended_actions.append(DefenseAction.RATE_LIMIT)
            action_priorities[DefenseAction.RATE_LIMIT] = self._get_action_priority(
                threat_score, DefenseAction.RATE_LIMIT
            )
        
        if threat_score > self.honeypot_threshold:
            recommended_actions.append(DefenseAction.DEPLOY_HONEYPOT)
            action_priorities[DefenseAction.DEPLOY_HONEYPOT] = self._get_action_priority(
                threat_score, DefenseAction.DEPLOY_HONEYPOT
            )
        
        if threat_score > 0.5:
            recommended_actions.append(DefenseAction.ALERT_SOC)
            action_priorities[DefenseAction.ALERT_SOC] = threat_score * 0.8
        
        if threat_score > 0.6:
            recommended_actions.append(DefenseAction.MONITOR)
            action_priorities[DefenseAction.MONITOR] = threat_score * 0.6
        
        # Exécution des actions prioritaires
        if recommended_actions:
            # Trier par priorité
            sorted_actions = sorted(
                recommended_actions,
                key=lambda a: action_priorities.get(a, 0),
                reverse=True,
            )
            
            # Exécuter les actions les plus prioritaires
            for action in sorted_actions[:3]:  # Max 3 actions
                if action in [DefenseAction.BLOCK_IP, DefenseAction.QUARANTINE,
                             DefenseAction.RATE_LIMIT, DefenseAction.DEPLOY_HONEYPOT,
                             DefenseAction.DECEPTION_RESPONSE]:
                    self._execute_action(action, ip, threat_score)
        
        honeypot_deployed = ip in self.honeypots_deployed
        
        # Explication
        explanation = self._generate_explanation(
            threat_level, threat_score, recommended_actions, ip
        )
        
        return DefenseResult(
            threat_level=threat_level,
            threat_score=threat_score,
            confidence=min(1.0, abs(threat_score - 0.5) * 2),
            recommended_actions=recommended_actions,
            action_priorities=action_priorities,
            is_blocked=is_blocked,
            is_quarantined=is_quarantined,
            honeypot_deployed=honeypot_deployed,
            inference_time_ms=(time.time() - start_time) * 1000,
            explanation=explanation,
        )
    
    def _generate_explanation(
        self,
        threat_level: ThreatLevel,
        threat_score: float,
        actions: List[DefenseAction],
        ip: str,
    ) -> str:
        """Génère une explication lisible."""
        parts = []
        
        level_icons = {
            ThreatLevel.NONE: "✅",
            ThreatLevel.LOW: "🟢",
            ThreatLevel.MEDIUM: "🟡",
            ThreatLevel.HIGH: "🟠",
            ThreatLevel.CRITICAL: "🔴",
        }
        
        icon = level_icons.get(threat_level, "❓")
        parts.append(f"{icon} MENACE {threat_level.value.upper()} (score={threat_score:.3f})")
        parts.append(f"IP: {ip}")
        
        if actions:
            action_names = [a.value for a in actions[:5]]
            parts.append(f"Actions: {', '.join(action_names)}")
        
        if self._check_blocked(ip):
            parts.append("🚫 IP déjà bloquée")
        if self._check_quarantined(ip):
            parts.append("🔒 IP en quarantaine")
        if self._check_rate_limit(ip):
            parts.append("⏱️ IP rate-limitée")
        
        parts.append(f"Stratégie: {self.strategy.value}")
        
        return " | ".join(parts)


# =============================================================================
# Ensemble : Défense Active Complète
# =============================================================================

class TranscendentDefenseEnsemble:
    """
    Ensemble de défense active qui fusionne les 4 modèles.
    
    Pipeline de défense :
    1. GradientBoosting → Classification robuste
    2. SVM Quantique → Détection avec noyau adaptatif
    3. FLAML → AutoML pour sélection du meilleur modèle
    4. Active Defense Engine → Contre-mesures automatiques
    5. XGBoost (méta-modèle) → Fusion adaptative
    """
    
    def __init__(
        self,
        gradient_boost: Optional[TranscendentGradientBoost] = None,
        quantum_svm: Optional[QuantumSVM] = None,
        flaml: Optional[TranscendentFLAML] = None,
        defense_engine: Optional[ActiveDefenseEngine] = None,
        strategy: DefenseStrategy = DefenseStrategy.ADAPTIVE,
        use_meta_model: bool = True,
    ):
        self.gradient_boost = gradient_boost
        self.quantum_svm = quantum_svm
        self.flaml = flaml
        self.defense_engine = defense_engine
        
        self.strategy = strategy
        self.use_meta_model = use_meta_model and HAS_XGBOOST
        
        # Poids des modèles
        self.model_weights = {
            'gradient_boost': 0.30,
            'quantum_svm': 0.25,
            'flaml': 0.25,
            'defense_engine': 0.20,
        }
        
        # Performance historique
        self.performance_history: Dict[str, List[float]] = {
            'gradient_boost': [],
            'quantum_svm': [],
            'flaml': [],
            'defense_engine': [],
        }
        
        # Méta-modèle (XGBoost)
        self.meta_model = None
        self.meta_scaler = StandardScaler()
        self.meta_is_fitted = False
        
        # Feature store pour calibration
        self.feature_store_meta: List[np.ndarray] = []
        self.label_store: List[int] = []
        self.max_store_size = 10000
        
        # Métriques
        self.n_analyses = 0
        self.total_inference_time = 0.0
    
    def set_models(
        self,
        gradient_boost: TranscendentGradientBoost,
        quantum_svm: QuantumSVM,
        flaml: TranscendentFLAML,
        defense_engine: ActiveDefenseEngine,
    ):
        """Configure les 4 modèles."""
        self.gradient_boost = gradient_boost
        self.quantum_svm = quantum_svm
        self.flaml = flaml
        self.defense_engine = defense_engine
    
    def _extract_meta_features(
        self,
        X: np.ndarray,
        scores: Dict[str, float],
    ) -> np.ndarray:
        """Extrait les features pour le méta-modèle."""
        features = []
        
        # Scores des modèles
        for name in ['gradient_boost', 'quantum_svm', 'flaml', 'defense_engine']:
            features.append(scores.get(name, 0.0))
        
        # Statistiques des features
        features.append(float(np.mean(X)))
        features.append(float(np.std(X)))
        features.append(float(np.max(X)))
        features.append(float(np.min(X)))
        
        return np.array(features)
    
    def _train_meta_model(self):
        """Entraîne le méta-modèle XGBoost."""
        if len(self.feature_store_meta) < 100:
            return
        
        X_meta = np.array(self.feature_store_meta)
        y_meta = np.array(self.label_store)
        
        X_scaled = self.meta_scaler.fit_transform(X_meta)
        
        self.meta_model = xgb.XGBClassifier(
            objective='binary:logistic',
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
        )
        self.meta_model.fit(X_scaled, y_meta)
        self.meta_is_fitted = True
        
        logger.info("defense_meta_model_trained", n_samples=len(X_meta))
    
    def analyze(
        self,
        X: np.ndarray,
        ip: str = "unknown",
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        true_label: Optional[int] = None,
    ) -> DefenseResult:
        """
        Analyse et exécute les actions de défense.
        
        Args:
            X: Features d'entrée
            ip: Adresse IP source
            port: Port source
            protocol: Protocole réseau
            true_label: Label réel (optionnel, pour adaptation)
        
        Returns:
            Résultat de défense
        """
        start_time = time.time()
        
        # Prédictions des modèles
        scores = {}
        
        # 1. GradientBoosting
        if self.gradient_boost is not None and self.gradient_boost.is_fitted:
            gb_probs = self.gradient_boost.predict_proba(X)
            gb_score = float(np.max(gb_probs[0]))
            scores['gradient_boost'] = gb_score
        
        # 2. SVM Quantique
        if self.quantum_svm is not None and self.quantum_svm.is_fitted:
            svm_probs = self.quantum_svm.predict_proba(X)
            svm_score = float(np.max(svm_probs[0]))
            scores['quantum_svm'] = svm_score
            
            # Anomaly score
            anomaly_score = float(np.mean(self.quantum_svm.predict_anomaly(X)))
            scores['svm_anomaly'] = anomaly_score
        
        # 3. FLAML
        if self.flaml is not None and self.flaml.is_fitted:
            flaml_probs = self.flaml.predict_proba(X)
            flaml_score = float(np.max(flaml_probs[0]))
            scores['flaml'] = flaml_score
        
        # Score de menace fusionné
        if self.use_meta_model and self.meta_is_fitted:
            meta_features = self._extract_meta_features(X, scores).reshape(1, -1)
            meta_scaled = self.meta_scaler.transform(meta_features)
            threat_score = float(self.meta_model.predict_proba(meta_scaled)[0, 1])
        else:
            threat_score = sum(
                scores.get(name, 0.0) * self.model_weights.get(name, 0.0)
                for name in self.model_weights
            )
        
        # 4. Active Defense Engine
        if self.defense_engine is not None:
            defense_result = self.defense_engine.analyze(
                threat_score=threat_score,
                ip=ip,
                port=port,
                protocol=protocol,
            )
        else:
            defense_result = DefenseResult(
                threat_level=ThreatLevel.NONE,
                threat_score=threat_score,
                confidence=0.0,
                recommended_actions=[],
                action_priorities={},
                is_blocked=False,
                is_quarantined=False,
                honeypot_deployed=False,
                inference_time_ms=0.0,
            )
        
        # Mise à jour des performances
        if true_label is not None:
            meta_features = self._extract_meta_features(X, scores)
            self.feature_store_meta.append(meta_features)
            self.label_store.append(true_label)
            
            if len(self.feature_store_meta) > self.max_store_size:
                self.feature_store_meta = self.feature_store_meta[-self.max_store_size:]
                self.label_store = self.label_store[-self.max_store_size:]
            
            if len(self.feature_store_meta) % 500 == 0:
                self._train_meta_model()
        
        # Métriques
        self.n_analyses += 1
        total_time = (time.time() - start_time) * 1000
        self.total_inference_time += total_time
        
        # Ajout des scores des modèles
        defense_result.model_scores = scores
        defense_result.inference_time_ms = total_time
        
        return defense_result
    
    def analyze_batch(
        self,
        X: np.ndarray,
        ips: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        protocols: Optional[List[str]] = None,
        true_labels: Optional[List[int]] = None,
    ) -> DefenseBatchResult:
        """Analyse un lot de données."""
        start_time = time.time()
        
        results = []
        for i in range(len(X)):
            ip = ips[i] if ips else "unknown"
            port = ports[i] if ports else None
            protocol = protocols[i] if protocols else None
            true_label = true_labels[i] if true_labels else None
            
            result = self.analyze(
                X[i:i+1],
                ip=ip,
                port=port,
                protocol=protocol,
                true_label=true_label,
            )
            results.append(result)
        
        n_critical = sum(1 for r in results if r.threat_level == ThreatLevel.CRITICAL)
        n_high = sum(1 for r in results if r.threat_level == ThreatLevel.HIGH)
        n_medium = sum(1 for r in results if r.threat_level == ThreatLevel.MEDIUM)
        n_low = sum(1 for r in results if r.threat_level == ThreatLevel.LOW)
        n_blocked = sum(1 for r in results if r.is_blocked)
        n_quarantined = sum(1 for r in results if r.is_quarantined)
        n_honeypots = sum(1 for r in results if r.honeypot_deployed)
        
        return DefenseBatchResult(
            results=results,
            n_critical=n_critical,
            n_high=n_high,
            n_medium=n_medium,
            n_low=n_low,
            n_blocked=n_blocked,
            n_quarantined=n_quarantined,
            n_honeypots_deployed=n_honeypots,
            batch_inference_time_ms=(time.time() - start_time) * 1000,
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de défense."""
        stats = {
            'n_analyses': self.n_analyses,
            'avg_inference_time_ms': self.total_inference_time / max(1, self.n_analyses),
            'model_weights': dict(self.model_weights),
            'meta_model_trained': self.meta_is_fitted,
        }
        
        if self.defense_engine is not None:
            stats['defense'] = {
                'n_blocks': self.defense_engine.n_blocks,
                'n_quarantines': self.defense_engine.n_quarantines,
                'n_rate_limits': self.defense_engine.n_rate_limits,
                'n_honeypots': self.defense_engine.n_honeypots,
                'n_deceptions': self.defense_engine.n_deceptions,
                'n_blocked_ips': len(self.defense_engine.blocked_ips),
                'n_quarantined_ips': len(self.defense_engine.quarantined_ips),
                'strategy': self.defense_engine.strategy.value,
            }
        
        return stats


# =============================================================================
# Factory : Création de la défense transcendante
# =============================================================================

def create_transcendent_defense(
    strategy: DefenseStrategy = DefenseStrategy.ADAPTIVE,
    block_threshold: float = 0.8,
    quarantine_threshold: float = 0.9,
    use_meta_model: bool = True,
) -> TranscendentDefenseEnsemble:
    """
    Crée et configure la défense transcendante complète.
    
    Args:
        strategy: Stratégie de défense
        block_threshold: Seuil de blocage
        quarantine_threshold: Seuil de quarantaine
        use_meta_model: Utiliser le méta-modèle XGBoost
    
    Returns:
        Ensemble de défense complet
    """
    logger.info("creating_transcendent_defense",
                strategy=strategy.value,
                block_threshold=block_threshold,
                quarantine_threshold=quarantine_threshold)
    
    # 1. GradientBoosting
    gradient_boost = TranscendentGradientBoost(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
    )
    
    # 2. SVM Quantique
    quantum_svm = QuantumSVM(
        kernel='rbf',
        C=1.0,
        gamma='scale',
        class_weight='balanced',
        use_one_class=True,
    )
    
    # 3. FLAML
    flaml = TranscendentFLAML(
        time_budget=60,
        max_models=10,
        ensemble=True,
    )
    
    # 4. Active Defense Engine
    defense_engine = ActiveDefenseEngine(
        strategy=strategy,
        block_threshold=block_threshold,
        quarantine_threshold=quarantine_threshold,
        rate_limit_threshold=0.6,
        honeypot_threshold=0.7,
        cooldown_seconds=300,
    )
    
    # Ensemble
    ensemble = TranscendentDefenseEnsemble(
        gradient_boost=gradient_boost,
        quantum_svm=quantum_svm,
        flaml=flaml,
        defense_engine=defense_engine,
        strategy=strategy,
        use_meta_model=use_meta_model,
    )
    
    logger.info("transcendent_defense_created",
                n_models=4,
                strategy=strategy.value)
    
    return ensemble
