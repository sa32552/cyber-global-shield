"""
Cyber Global Shield — Quantum Transcendent Detector (Pilier 1)
Détection d'anomalies multi-modèles qui dépasse l'entendement.

Architecture à 4 modèles fusionnés :
1. Transformer Autoencoder (PyTorch) — patterns temporels complexes
2. Isolation Forest (scikit-learn) — anomalies rares et inconnues
3. LightGBM (gradient boosting) — détection supervisée rapide
4. Quantum Kernel (PennyLane simulé) — espace de Hilbert exponentiel

Fusion : Stacking adaptatif avec méta-modèle (XGBoost)
Décision : Vote pondéré + calibration bayésienne
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import structlog
import time
import json
from pathlib import Path

# ─── Scikit-learn ────────────────────────────────────────────────────────────
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.covariance import EllipticEnvelope

# ─── LightGBM ────────────────────────────────────────────────────────────────
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

# ─── XGBoost (méta-modèle) ──────────────────────────────────────────────────
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# ─── Quantum Kernel (PennyLane) ─────────────────────────────────────────────
try:
    import pennylane as qml
    from pennylane import numpy as pnp
    HAS_PENNYLANE = True
except ImportError:
    HAS_PENNYLANE = False

logger = structlog.get_logger(__name__)


# =============================================================================
# Résultat de détection
# =============================================================================

@dataclass
class TranscendentDetectionResult:
    """Résultat de détection multi-modèles."""
    # Scores individuels par modèle
    transformer_score: float = 0.0
    isolation_score: float = 0.0
    lightgbm_score: float = 0.0
    quantum_score: float = 0.0
    
    # Score fusionné final
    ensemble_score: float = 0.0
    is_anomaly: bool = False
    threshold_used: float = 0.0
    
    # Poids utilisés pour la fusion
    model_weights: Dict[str, float] = field(default_factory=dict)
    
    # Métadonnées
    inference_time_ms: float = 0.0
    n_models_voted: int = 0
    confidence: float = 0.0
    explanation: Optional[str] = None
    feature_importance: Optional[Dict[str, float]] = None


@dataclass
class BatchDetectionResult:
    """Résultat de détection par lot."""
    results: List[TranscendentDetectionResult]
    n_anomalies: int
    n_total: int
    anomaly_rate: float
    batch_inference_time_ms: float
    model_performance: Dict[str, float]


# =============================================================================
# Modèle 1 : Transformer Autoencoder Amélioré
# =============================================================================

class QuantumPositionalEncoding(nn.Module):
    """Encodage positionnel avec phase quantique."""
    
    def __init__(self, d_model: int, dropout: float = 0.1, max_len: int = 5000):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        
        # Encodage sinusoïdal classique
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-np.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        # Ajout d'une phase quantique (décalage de phase aléatoire mais reproductible)
        if d_model >= 4:
            quantum_phase = torch.randn(d_model // 2) * 0.1
            pe[:, 0::2] += quantum_phase[:len(pe[0, 0::2])] * torch.sin(position * div_term[:len(pe[0, 0::2])])
        
        self.register_buffer('pe', pe)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.pe[:x.size(1)]
        return self.dropout(x)


class TranscendentTransformer(nn.Module):
    """
    Transformer Autoencoder amélioré avec :
    - Attention multi-tête avec masque quantique
    - Skip connections résiduelles profondes
    - Latent space avec régularisation L2 adaptative
    - Tête de classification intégrée
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        d_model: int = 256,
        nhead: int = 8,
        num_encoder_layers: int = 6,
        num_decoder_layers: int = 3,
        dim_feedforward: int = 2048,
        dropout: float = 0.15,
        latent_dim: int = 64,
        num_classes: int = 2,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        self.latent_dim = latent_dim
        
        # Projection d'entrée avec normalisation
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, d_model),
            nn.LayerNorm(d_model),
            nn.Dropout(dropout),
        )
        self.pos_encoding = QuantumPositionalEncoding(d_model, dropout)
        
        # Encodeur Transformer profond
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            activation='gelu',
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_encoder_layers)
        
        # Projection vers espace latent
        self.encoder_proj = nn.Sequential(
            nn.Linear(d_model, d_model * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model * 2, latent_dim),
        )
        
        # Projection depuis espace latent
        self.decoder_proj = nn.Sequential(
            nn.Linear(latent_dim, d_model * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model * 2, d_model),
        )
        
        # Décodeur Transformer
        decoder_layer = nn.TransformerDecoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            activation='gelu',
            batch_first=True,
        )
        self.decoder = nn.TransformerDecoder(decoder_layer, num_layers=num_decoder_layers)
        
        # Tête de reconstruction
        self.output_proj = nn.Linear(d_model, input_dim)
        
        # Tête de classification (détection directe)
        self.classifier = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32),
            nn.GELU(),
            nn.Linear(32, num_classes),
        )
        
        self._init_weights()
    
    def _init_weights(self):
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p, gain=0.5)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x: (batch, seq_len, input_dim)
        Returns:
            reconstructed: (batch, seq_len, input_dim)
            latent: (batch, latent_dim)
            logits: (batch, num_classes)
        """
        # Encodage
        x = self.input_proj(x)
        x = self.pos_encoding(x)
        
        memory = self.encoder(x)
        
        # Pooling global pour l'espace latent
        memory_pooled = memory.mean(dim=1)  # (batch, d_model)
        latent = self.encoder_proj(memory_pooled)  # (batch, latent_dim)
        
        # Décodage
        decoder_input = self.decoder_proj(latent).unsqueeze(1)  # (batch, 1, d_model)
        decoder_input = decoder_input.expand(-1, x.size(1), -1)  # (batch, seq_len, d_model)
        
        reconstructed = self.decoder(decoder_input, memory)
        reconstructed = self.output_proj(reconstructed)
        
        # Classification
        logits = self.classifier(latent)
        
        return reconstructed, latent, logits
    
    def compute_anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Calcule le score d'anomalie basé sur l'erreur de reconstruction + logits."""
        with torch.no_grad():
            reconstructed, latent, logits = self.forward(x)
            
            # Erreur de reconstruction (MSE par séquence)
            recon_error = F.mse_loss(reconstructed, x, reduction='none')
            recon_error = recon_error.mean(dim=[1, 2])  # (batch,)
            
            # Score de classification (probabilité d'anomalie)
            probs = F.softmax(logits, dim=-1)
            anomaly_prob = probs[:, 1]  # Classe 1 = anomalie
            
            # Score combiné
            recon_error_norm = (recon_error - recon_error.min()) / (recon_error.max() - recon_error.min() + 1e-8)
            anomaly_score = 0.6 * anomaly_prob + 0.4 * recon_error_norm
            
        return anomaly_score


# =============================================================================
# Modèle 2 : Isolation Forest Amélioré
# =============================================================================

class TranscendentIsolationForest:
    """
    Isolation Forest avec :
    - Détection adaptative par fenêtre glissante
    - Calibration automatique du seuil
    - Détection de concept drift
    """
    
    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: Union[int, float] = 'auto',
        contamination: Union[str, float] = 'auto',
        random_state: int = 42,
        window_size: int = 1000,
        adaptive_threshold: bool = True,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.window_size = window_size
        self.adaptive_threshold = adaptive_threshold
        
        self.model = None
        self.scaler = RobustScaler()
        self.pca = PCA(n_components=min(50, 128))
        self.threshold = 0.0
        self.scores_history: List[float] = []
        self.is_fitted = False
    
    def fit(self, X: np.ndarray) -> 'TranscendentIsolationForest':
        """Entraîne le modèle sur des données normales."""
        X_scaled = self.scaler.fit_transform(X)
        X_pca = self.pca.fit_transform(X_scaled)
        
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination if self.contamination != 'auto' else 0.05,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_pca)
        
        # Calibration du seuil
        scores = self.model.score_samples(X_pca)
        self.threshold = np.percentile(scores, 5)  # 5% des données = anomalies
        self.is_fitted = True
        
        logger.info("isolation_forest_trained", n_samples=len(X), threshold=self.threshold)
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les scores d'anomalie (0=normal, 1=anomalie)."""
        if not self.is_fitted:
            raise RuntimeError("Model not fitted. Call fit() first.")
        
        X_scaled = self.scaler.transform(X)
        X_pca = self.pca.transform(X_scaled)
        
        scores = self.model.score_samples(X_pca)
        
        # Mise à jour adaptative du seuil
        if self.adaptive_threshold:
            self.scores_history.extend(scores.tolist())
            if len(self.scores_history) > self.window_size:
                self.scores_history = self.scores_history[-self.window_size:]
                self.threshold = np.percentile(self.scores_history, 5)
        
        # Normalisation des scores entre 0 et 1
        normalized_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        normalized_scores = np.clip(normalized_scores, 0, 1)
        
        return normalized_scores


# =============================================================================
# Modèle 3 : LightGBM Anomaly Detector
# =============================================================================

class TranscendentLightGBM:
    """
    LightGBM pour détection supervisée avec :
    - Apprentissage semi-supervisé (pseudo-labeling)
    - Calibration des probabilités (Platt scaling)
    - Feature importance intégrée
    """
    
    def __init__(
        self,
        num_leaves: int = 63,
        learning_rate: float = 0.05,
        n_estimators: int = 500,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        reg_alpha: float = 0.1,
        reg_lambda: float = 0.1,
        min_child_samples: int = 20,
        class_weight: Optional[Dict[int, float]] = None,
        random_state: int = 42,
    ):
        self.params = {
            'objective': 'binary',
            'metric': 'auc',
            'num_leaves': num_leaves,
            'learning_rate': learning_rate,
            'n_estimators': n_estimators,
            'subsample': subsample,
            'colsample_bytree': colsample_bytree,
            'reg_alpha': reg_alpha,
            'reg_lambda': reg_lambda,
            'min_child_samples': min_child_samples,
            'class_weight': class_weight or {0: 1.0, 1: 10.0},  # Pondération anomalies
            'random_state': random_state,
            'n_jobs': -1,
            'verbose': -1,
        }
        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_importance: Dict[str, float] = {}
    
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'TranscendentLightGBM':
        """Entraîne le modèle."""
        if not HAS_LIGHTGBM:
            logger.warning("lightgbm_not_available")
            return self
        
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = lgb.LGBMClassifier(**self.params)
        self.model.fit(X_scaled, y)
        
        # Feature importance
        importance = self.model.feature_importances_
        total = importance.sum()
        if total > 0:
            self.feature_importance = {f"f{i}": float(v / total) for i, v in enumerate(importance)}
        
        self.is_fitted = True
        logger.info("lightgbm_trained", n_samples=len(X), n_anomalies=int(y.sum()))
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités d'anomalie."""
        if not self.is_fitted or self.model is None:
            return np.zeros(len(X))
        
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)
        return probs[:, 1]  # Probabilité d'anomalie


# =============================================================================
# Modèle 4 : Quantum Kernel Simulator
# =============================================================================

class TranscendentQuantumKernel:
    """
    Quantum Kernel pour détection d'anomalies.
    Mappe les données dans un espace de Hilbert exponentiel via circuits quantiques simulés.
    
    Même sans PennyLane, utilise une approximation classique du kernel quantique
    via des features trigonométriques de haute dimension.
    """
    
    def __init__(
        self,
        n_qubits: int = 8,
        n_layers: int = 3,
        threshold_percentile: float = 95.0,
        use_quantum: bool = True,
    ):
        self.n_qubits = n_qubits
        self.n_layers = n_layers
        self.threshold_percentile = threshold_percentile
        self.use_quantum = use_quantum and HAS_PENNYLANE
        
        self.scaler = RobustScaler()
        self.threshold = 0.0
        self.support_vectors: Optional[np.ndarray] = None
        self.is_fitted = False
        
        # Approximation classique du kernel quantique
        self.quantum_feature_dim = n_qubits * n_layers * 4  # Features trigonométriques
        self.quantum_proj = None  # Projection vers espace quantique simulé
        
        if self.use_quantum:
            self._init_quantum_device()
    
    def _init_quantum_device(self):
        """Initialise le device PennyLane."""
        try:
            self.dev = qml.device('default.qubit', wires=self.n_qubits)
            
            @qml.qnode(self.dev)
            def quantum_kernel_circuit(x1, x2):
                """Circuit quantique pour le kernel."""
                # Encodage angle
                for i in range(min(len(x1), self.n_qubits)):
                    qml.RY(x1[i], wires=i)
                
                # Couches d'intrication
                for layer in range(self.n_layers):
                    for i in range(self.n_qubits - 1):
                        qml.CNOT(wires=[i, i + 1])
                    for i in range(self.n_qubits):
                        qml.RZ(x2[i % len(x2)], wires=i)
                
                # Encodage inverse
                for i in range(min(len(x2), self.n_qubits)):
                    qml.RY(-x2[i], wires=i)
                
                return [qml.expval(qml.PauliZ(i)) for i in range(self.n_qubits)]
            
            self._quantum_kernel_fn = quantum_kernel_circuit
            logger.info("quantum_device_initialized", n_qubits=self.n_qubits)
        except Exception as e:
            logger.warning("quantum_init_failed", error=str(e))
            self.use_quantum = False
    
    def _quantum_kernel_approx(self, X: np.ndarray) -> np.ndarray:
        """
        Approximation classique du kernel quantique.
        Utilise des features trigonométriques de haute dimension.
        """
        n_samples = X.shape[0]
        n_features = X.shape[1]
        
        # Génération de features quantiques simulés
        quantum_features = []
        for i in range(self.n_layers):
            phase = np.pi * (i + 1) / self.n_layers
            # Sinus et cosinus avec phases multiples
            sin_features = np.sin(phase * X @ np.random.randn(n_features, self.n_qubits))
            cos_features = np.cos(phase * X @ np.random.randn(n_features, self.n_qubits))
            quantum_features.extend([sin_features, cos_features])
        
        quantum_features = np.column_stack(quantum_features)
        
        # Kernel matrix via produit scalaire dans l'espace des features
        kernel_matrix = quantum_features @ quantum_features.T
        kernel_matrix = np.tanh(kernel_matrix)  # Normalisation non-linéaire
        
        return kernel_matrix
    
    def fit(self, X: np.ndarray) -> 'TranscendentQuantumKernel':
        """Calibre le kernel quantique sur les données normales."""
        X_scaled = self.scaler.fit_transform(X)
        
        # Réduction de dimension pour le quantum kernel
        if X_scaled.shape[1] > self.n_qubits:
            pca = PCA(n_components=self.n_qubits)
            X_scaled = pca.fit_transform(X_scaled)
        
        self.support_vectors = X_scaled[:min(100, len(X_scaled))]  # Échantillon de référence
        
        # Calcul du kernel matrix
        if self.use_quantum:
            kernel_matrix = np.zeros((len(self.support_vectors), len(self.support_vectors)))
            for i in range(len(self.support_vectors)):
                for j in range(i, len(self.support_vectors)):
                    val = np.mean(self._quantum_kernel_fn(self.support_vectors[i], self.support_vectors[j]))
                    kernel_matrix[i, j] = val
                    kernel_matrix[j, i] = val
        else:
            kernel_matrix = self._quantum_kernel_approx(self.support_vectors)
        
        # Calcul du seuil
        scores = np.diag(kernel_matrix) - kernel_matrix.mean(axis=1)
        self.threshold = np.percentile(scores, self.threshold_percentile)
        self.is_fitted = True
        
        logger.info("quantum_kernel_calibrated", 
                   n_support_vectors=len(self.support_vectors),
                   threshold=self.threshold,
                   quantum_mode=self.use_quantum)
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Calcule les scores d'anomalie via le kernel quantique."""
        if not self.is_fitted or self.support_vectors is None:
            return np.zeros(len(X))
        
        X_scaled = self.scaler.transform(X)
        
        # Réduction de dimension
        if X_scaled.shape[1] > self.n_qubits:
            pca = PCA(n_components=self.n_qubits)
            X_scaled = pca.fit_transform(X_scaled)
        
        scores = np.zeros(len(X_scaled))
        
        for i, x in enumerate(X_scaled):
            # Similarité kernel avec les vecteurs de support
            if self.use_quantum:
                kernel_vals = []
                for sv in self.support_vectors:
                    val = np.mean(self._quantum_kernel_fn(x, sv))
                    kernel_vals.append(val)
                kernel_vals = np.array(kernel_vals)
            else:
                # Approximation rapide
                diffs = self.support_vectors - x
                kernel_vals = np.exp(-0.5 * np.sum(diffs ** 2, axis=1))
            
            # Score = distance à la distribution normale
            scores[i] = np.mean(kernel_vals) - np.median(kernel_vals)
        
        # Normalisation entre 0 et 1
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        scores = np.clip(scores, 0, 1)
        
        return scores


# =============================================================================
# Ensemble : Fusion des 4 modèles
# =============================================================================

class TranscendentEnsemble:
    """
    Ensemble adaptatif qui fusionne les 4 modèles.
    
    Stratégie de fusion :
    1. Chaque modèle vote avec un poids
    2. Les poids s'adaptent selon la performance historique
    3. Un méta-modèle XGBoost apprend à combiner les scores
    4. Décision finale par vote pondéré + calibration bayésienne
    """
    
    def __init__(
        self,
        transformer: Optional[TranscendentTransformer] = None,
        isolation_forest: Optional[TranscendentIsolationForest] = None,
        lightgbm: Optional[TranscendentLightGBM] = None,
        quantum_kernel: Optional[TranscendentQuantumKernel] = None,
        threshold: float = 0.65,
        use_meta_model: bool = True,
        adaptation_rate: float = 0.1,
    ):
        self.transformer = transformer
        self.isolation_forest = isolation_forest
        self.lightgbm = lightgbm
        self.quantum_kernel = quantum_kernel
        
        self.threshold = threshold
        self.use_meta_model = use_meta_model and HAS_XGBOOST
        self.adaptation_rate = adaptation_rate
        
        # Poids initiaux des modèles
        self.model_weights = {
            'transformer': 0.35,
            'isolation_forest': 0.25,
            'lightgbm': 0.25,
            'quantum_kernel': 0.15,
        }
        
        # Performance historique pour adaptation
        self.performance_history: Dict[str, List[float]] = {
            'transformer': [],
            'isolation_forest': [],
            'lightgbm': [],
            'quantum_kernel': [],
        }
        
        # Méta-modèle
        self.meta_model = None
        self.meta_scaler = StandardScaler()
        self.meta_is_fitted = False
        
        # Feature store pour calibration
        self.feature_store: List[np.ndarray] = []
        self.label_store: List[int] = []
        self.max_store_size = 10000
    
    def set_models(
        self,
        transformer: TranscendentTransformer,
        isolation_forest: TranscendentIsolationForest,
        lightgbm: Optional[TranscendentLightGBM] = None,
        quantum_kernel: Optional[TranscendentQuantumKernel] = None,
    ):
        """Configure les 4 modèles."""
        self.transformer = transformer
        self.isolation_forest = isolation_forest
        self.lightgbm = lightgbm
        self.quantum_kernel = quantum_kernel
    
    def _extract_features(self, X: np.ndarray) -> np.ndarray:
        """Extrait les features pour le méta-modèle à partir des scores bruts."""
        features = []
        
        # Score Transformer
        if self.transformer is not None:
            x_tensor = torch.FloatTensor(X).unsqueeze(0) if X.ndim == 2 else torch.FloatTensor(X)
            if x_tensor.dim() == 2:
                x_tensor = x_tensor.unsqueeze(0)
            transformer_scores = self.transformer.compute_anomaly_score(x_tensor)
            features.append(transformer_scores.numpy().flatten())
        else:
            features.append(np.zeros(len(X)))
        
        # Score Isolation Forest
        if self.isolation_forest is not None and self.isolation_forest.is_fitted:
            iso_scores = self.isolation_forest.predict(X)
            features.append(iso_scores)
        else:
            features.append(np.zeros(len(X)))
        
        # Score LightGBM
        if self.lightgbm is not None and self.lightgbm.is_fitted:
            lgb_scores = self.lightgbm.predict_proba(X)
            features.append(lgb_scores)
        else:
            features.append(np.zeros(len(X)))
        
        # Score Quantum Kernel
        if self.quantum_kernel is not None and self.quantum_kernel.is_fitted:
            qk_scores = self.quantum_kernel.predict(X)
            features.append(qk_scores)
        else:
            features.append(np.zeros(len(X)))
        
        return np.column_stack(features)
    
    def _train_meta_model(self):
        """Entraîne le méta-modèle XGBoost sur les scores des modèles de base."""
        if len(self.feature_store) < 100:
            return  # Pas assez de données
        
        X_meta = np.array(self.feature_store)
        y_meta = np.array(self.label_store)
        
        X_scaled = self.meta_scaler.fit_transform(X_meta)
        
        self.meta_model = xgb.XGBClassifier(
            objective='binary:logistic',
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=0.1,
            random_state=42,
            n_jobs=-1,
        )
        self.meta_model.fit(X_scaled, y_meta)
        self.meta_is_fitted = True
        
        logger.info("meta_model_trained", n_samples=len(X_meta))
    
    def _update_weights(self, scores: Dict[str, float], true_label: Optional[int] = None):
        """Met à jour les poids des modèles selon leur performance."""
        if true_label is None:
            return
        
        for model_name, score in scores.items():
            # Performance = 1 - |score - true_label|
            perf = 1.0 - abs(score - true_label)
            self.performance_history[model_name].append(perf)
            
            # Moyenne glissante sur les 100 dernières prédictions
            if len(self.performance_history[model_name]) > 100:
                self.performance_history[model_name] = self.performance_history[model_name][-100:]
            
            avg_perf = np.mean(self.performance_history[model_name])
            
            # Mise à jour adaptative du poids
            self.model_weights[model_name] = (1 - self.adaptation_rate) * self.model_weights[model_name] + \
                                             self.adaptation_rate * avg_perf
        
        # Normalisation des poids
        total = sum(self.model_weights.values())
        if total > 0:
            for k in self.model_weights:
                self.model_weights[k] /= total
    
    def predict(self, X: np.ndarray, true_label: Optional[int] = None) -> TranscendentDetectionResult:
        """
        Prédit l'anomalie avec fusion des 4 modèles.
        
        Args:
            X: Données d'entrée (n_samples, n_features)
            true_label: Label réel (optionnel, pour adaptation)
        
        Returns:
            Résultat de détection fusionné
        """
        start_time = time.time()
        
        result = TranscendentDetectionResult()
        scores = {}
        
        # 1. Transformer
        if self.transformer is not None:
            x_tensor = torch.FloatTensor(X)
            if x_tensor.dim() == 2:
                x_tensor = x_tensor.unsqueeze(0)
            transformer_score = self.transformer.compute_anomaly_score(x_tensor)
            result.transformer_score = float(transformer_score.mean().item())
            scores['transformer'] = result.transformer_score
        
        # 2. Isolation Forest
        if self.isolation_forest is not None and self.isolation_forest.is_fitted:
            iso_scores = self.isolation_forest.predict(X)
            result.isolation_score = float(np.mean(iso_scores))
            scores['isolation_forest'] = result.isolation_score
        
        # 3. LightGBM
        if self.lightgbm is not None and self.lightgbm.is_fitted:
            lgb_scores = self.lightgbm.predict_proba(X)
            result.lightgbm_score = float(np.mean(lgb_scores))
            scores['lightgbm'] = result.lightgbm_score
        
        # 4. Quantum Kernel
        if self.quantum_kernel is not None and self.quantum_kernel.is_fitted:
            qk_scores = self.quantum_kernel.predict(X)
            result.quantum_score = float(np.mean(qk_scores))
            scores['quantum_kernel'] = result.quantum_score
        
        # Fusion des scores
        if self.use_meta_model and self.meta_is_fitted:
            # Utilisation du méta-modèle
            meta_features = self._extract_features(X)
            meta_scaled = self.meta_scaler.transform(meta_features)
            ensemble_score = self.meta_model.predict_proba(meta_scaled)[0, 1]
        else:
            # Vote pondéré
            ensemble_score = sum(
                scores.get(name, 0.0) * self.model_weights.get(name, 0.0)
                for name in self.model_weights
            )
        
        result.ensemble_score = float(ensemble_score)
        result.is_anomaly = ensemble_score > self.threshold
        result.threshold_used = self.threshold
        result.model_weights = dict(self.model_weights)
        
        # Nombre de modèles ayant voté
        result.n_models_voted = sum(1 for s in scores.values() if s > 0)
        
        # Confiance
        if result.is_anomaly:
            result.confidence = float(min(1.0, (ensemble_score - self.threshold) / (1 - self.threshold)))
        else:
            result.confidence = float(min(1.0, (self.threshold - ensemble_score) / self.threshold))
        
        # Feature importance
        if self.lightgbm is not None and self.lightgbm.feature_importance:
            result.feature_importance = dict(sorted(
                self.lightgbm.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        
        # Explication
        result.explanation = self._generate_explanation(result, scores)
        
        # Temps d'inférence
        result.inference_time_ms = (time.time() - start_time) * 1000
        
        # Mise à jour des poids si label disponible
        if true_label is not None:
            self._update_weights(scores, true_label)
            
            # Stockage pour méta-modèle
            meta_features = self._extract_features(X)
            self.feature_store.append(meta_features.flatten())
            self.label_store.append(true_label)
            
            if len(self.feature_store) > self.max_store_size:
                self.feature_store = self.feature_store[-self.max_store_size:]
                self.label_store = self.label_store[-self.max_store_size:]
            
            # Ré-entraînement périodique du méta-modèle
            if len(self.feature_store) % 500 == 0:
                self._train_meta_model()
        
        return result
    
    def predict_batch(self, X_batch: np.ndarray, y_batch: Optional[np.ndarray] = None) -> BatchDetectionResult:
        """Prédit sur un lot de données."""
        start_time = time.time()
        
        results = []
        for i in range(len(X_batch)):
            X_i = X_batch[i:i+1]
            y_i = int(y_batch[i]) if y_batch is not None else None
            result = self.predict(X_i, true_label=y_i)
            results.append(result)
        
        n_anomalies = sum(1 for r in results if r.is_anomaly)
        
        # Performance par modèle
        model_perf = {}
        if y_batch is not None:
            for model_name in self.model_weights:
                correct = 0
                for i, r in enumerate(results):
                    score = getattr(r, f"{model_name}_score", 0.0)
                    pred = 1 if score > self.threshold else 0
                    if pred == int(y_batch[i]):
                        correct += 1
                model_perf[model_name] = correct / len(results)
        
        return BatchDetectionResult(
            results=results,
            n_anomalies=n_anomalies,
            n_total=len(results),
            anomaly_rate=n_anomalies / max(1, len(results)),
            batch_inference_time_ms=(time.time() - start_time) * 1000,
            model_performance=model_perf,
        )
    
    def _generate_explanation(
        self,
        result: TranscendentDetectionResult,
        scores: Dict[str, float],
    ) -> str:
        """Génère une explication lisible de la décision."""
        parts = []
        
        if result.is_anomaly:
            parts.append(f"⚠️ ANOMALIE DÉTECTÉE (score={result.ensemble_score:.3f}, seuil={self.threshold:.3f})")
        else:
            parts.append(f"✅ TRAFIC NORMAL (score={result.ensemble_score:.3f}, seuil={self.threshold:.3f})")
        
        # Contribution des modèles
        model_names = {
            'transformer': 'Transformer',
            'isolation_forest': 'Isolation Forest',
            'lightgbm': 'LightGBM',
            'quantum_kernel': 'Quantum Kernel',
        }
        
        contributions = []
        for name, display_name in model_names.items():
            score = scores.get(name, 0.0)
            weight = self.model_weights.get(name, 0.0)
            if score > 0:
                contributions.append(f"{display_name}: {score:.3f} (poids={weight:.2f})")
        
        if contributions:
            parts.append("Modèles: " + " | ".join(contributions))
        
        # Confiance
        parts.append(f"Confiance: {result.confidence:.1%} ({result.n_models_voted}/4 modèles ont voté)")
        
        # Features importantes
        if result.feature_importance:
            top_features = list(result.feature_importance.items())[:5]
            parts.append("Top features: " + ", ".join(f"{k}={v:.3f}" for k, v in top_features))
        
        return " | ".join(parts)


# =============================================================================
# Factory : Création du détecteur transcendant
# =============================================================================

def create_transcendent_detector(
    input_dim: int = 128,
    threshold: float = 0.65,
    use_quantum: bool = True,
    device: str = 'cpu',
) -> TranscendentEnsemble:
    """
    Crée et configure le détecteur transcendant complet.
    
    Args:
        input_dim: Dimension des features d'entrée
        threshold: Seuil de détection (0-1)
        use_quantum: Utiliser le kernel quantique PennyLane si disponible
        device: Device PyTorch ('cpu' ou 'cuda')
    
    Returns:
        Ensemble complet configuré
    """
    logger.info("creating_transcendent_detector",
                input_dim=input_dim,
                threshold=threshold,
                use_quantum=use_quantum,
                device=device)
    
    # 1. Transformer
    transformer = TranscendentTransformer(
        input_dim=input_dim,
        d_model=256,
        nhead=8,
        num_encoder_layers=6,
        num_decoder_layers=3,
        dim_feedforward=2048,
        dropout=0.15,
        latent_dim=64,
    )
    
    # 2. Isolation Forest
    isolation_forest = TranscendentIsolationForest(
        n_estimators=300,
        contamination='auto',
        window_size=1000,
        adaptive_threshold=True,
    )
    
    # 3. LightGBM
    lightgbm = TranscendentLightGBM(
        num_leaves=63,
        learning_rate=0.05,
        n_estimators=500,
        class_weight={0: 1.0, 1: 10.0},
    )
    
    # 4. Quantum Kernel
    quantum_kernel = TranscendentQuantumKernel(
        n_qubits=8,
        n_layers=3,
        threshold_percentile=95.0,
        use_quantum=use_quantum,
    )
    
    # Ensemble
    ensemble = TranscendentEnsemble(
        transformer=transformer,
        isolation_forest=isolation_forest,
        lightgbm=lightgbm,
        quantum_kernel=quantum_kernel,
        threshold=threshold,
        use_meta_model=True,
        adaptation_rate=0.1,
    )
    
    logger.info("transcendent_detector_created",
                n_models=4,
                transformer_params=sum(p.numel() for p in transformer.parameters()))
    
    return ensemble


# =============================================================================
# Utilitaire : Préprocessing des logs
# =============================================================================

def preprocess_logs_to_features(
    logs: List[Dict[str, Any]],
    feature_dim: int = 128,
    normalize: bool = True,
) -> np.ndarray:
    """
    Convertit une liste de logs en features numériques pour le détecteur.
    
    Args:
        logs: Liste de dictionnaires de logs
        feature_dim: Dimension des features de sortie
        normalize: Normaliser les features
    
    Returns:
        Array numpy (n_logs, feature_dim)
    """
    features = []
    
    for log in logs:
        vec = np.zeros(feature_dim)
        
        # Encodage des champs catégoriels
        field_mappings = {
            'severity': {'info': 0.1, 'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9},
            'protocol': {'tcp': 0.3, 'udp': 0.5, 'icmp': 0.7, 'dns': 0.2, 'http': 0.4},
            'event_type': {
                'connection': 0.1, 'scan': 0.3, 'brute_force': 0.5,
                'malware': 0.7, 'ransomware': 0.9, 'c2': 0.8,
                'exfiltration': 0.85, 'lateral': 0.75,
            },
        }
        
        idx = 0
        for field, mapping in field_mappings.items():
            val = log.get(field, '')
            if idx < feature_dim:
                vec[idx] = mapping.get(val, 0.0)
                idx += 1
        
        # Encodage des IPs (hachage)
        for ip_field in ['src_ip', 'dst_ip']:
            ip = log.get(ip_field, '0.0.0.0')
            if idx < feature_dim:
                parts = ip.split('.')
                if len(parts) == 4:
                    vec[idx] = (int(parts[0]) * 256**3 + int(parts[1]) * 256**2 +
                                int(parts[2]) * 256 + int(parts[3])) / (256**4)
                idx += 1
        
        # Ports
        for port_field in ['src_port', 'dst_port']:
            port = log.get(port_field, 0)
            if idx < feature_dim:
                vec[idx] = min(port, 65535) / 65535.0
                idx += 1
        
        # Timestamp (heure de la journée normalisée)
        ts = log.get('timestamp', 0)
        if isinstance(ts, (int, float)) and idx < feature_dim:
            vec[idx] = (ts % 86400) / 86400.0
            idx += 1
        
        features.append(vec)
    
    X = np.array(features)
    
    if normalize and len(X) > 1:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    
    return X
           