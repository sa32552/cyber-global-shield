"""
Cyber Global Shield — Ultra-Pointer Biometrics & Identity Module (Niveau 9)
=============================================================================

4 modèles de pointe pour la biométrie comportementale :

1. Keystroke Dynamics (RNN + Attention) — Analyse de frappe au clavier
2. Mouse Dynamics (CNN + LSTM) — Analyse de mouvements de souris
3. Gait Recognition (Skeleton-based GNN) — Reconnaissance de démarche
4. Behavioral Embeddings (Contrastive Learning) — Embeddings comportementaux

Chaque module peut fonctionner indépendamment ou via l'ensemble biométrique.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field
from collections import deque, defaultdict
from datetime import datetime, timezone
import structlog
import math
import warnings

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BiometricResult:
    """Résultat d'analyse biométrique unifié."""
    score: float
    is_anomaly: bool
    confidence: float
    analysis_type: str  # "keystroke", "mouse", "gait", "behavioral"
    model_name: str
    explanation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    inference_time_ms: float = 0.0


@dataclass
class KeystrokeSequence:
    """Séquence de frappe au clavier."""
    key_codes: np.ndarray  # codes des touches
    timestamps: np.ndarray  # timestamps en ms
    durations: np.ndarray  # durée de chaque pression
    intervals: np.ndarray  # intervalle entre touches
    n_keys: int = 0


@dataclass
class MouseTrajectory:
    """Trajectoire de souris."""
    x: np.ndarray  # positions x
    y: np.ndarray  # positions y
    timestamps: np.ndarray  # timestamps
    buttons: np.ndarray  # boutons pressés
    scroll: np.ndarray  # scroll
    velocity: Optional[np.ndarray] = None
    acceleration: Optional[np.ndarray] = None


@dataclass
class SkeletonPose:
    """Pose de squelette pour reconnaissance de démarche."""
    keypoints: np.ndarray  # (n_joints, 3) — x, y, confidence
    timestamps: np.ndarray
    n_joints: int = 17  # COCO keypoints


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: KEYSTROKE DYNAMICS (RNN + Attention)
# ═══════════════════════════════════════════════════════════════════════════

class KeystrokeAttention(nn.Module):
    """Mécanisme d'attention pour séquences de frappe."""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attn = nn.Linear(hidden_dim * 2, 1)
        self.softmax = nn.Softmax(dim=1)

    def forward(
        self, hidden: torch.Tensor, encoder_outputs: torch.Tensor
    ) -> torch.Tensor:
        # hidden: (B, hidden_dim), encoder_outputs: (B, T, hidden_dim)
        hidden = hidden.unsqueeze(1).expand(-1, encoder_outputs.size(1), -1)
        energy = torch.cat([hidden, encoder_outputs], dim=2)
        attn_weights = self.softmax(self.attn(energy).squeeze(2))
        context = torch.bmm(attn_weights.unsqueeze(1), encoder_outputs).squeeze(1)
        return context


class KeystrokeRNNAttention(nn.Module):
    """
    Keystroke Dynamics avec RNN + Attention.
    Analyse le rythme de frappe pour détecter les usurpations d'identité.
    """

    def __init__(
        self,
        input_dim: int = 4,  # key_code, duration, interval, velocity
        hidden_dim: int = 128,
        n_layers: int = 2,
        n_classes: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)

        self.lstm = nn.LSTM(
            hidden_dim, hidden_dim, n_layers,
            batch_first=True, bidirectional=True,
            dropout=dropout if n_layers > 1 else 0,
        )

        self.attention = KeystrokeAttention(hidden_dim * 2)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, input_dim)
        x = self.input_proj(x)

        lstm_out, (hidden, cell) = self.lstm(x)
        # lstm_out: (B, T, hidden*2)
        # hidden: (n_layers*2, B, hidden)

        # Use last layer's hidden state
        hidden_last = torch.cat([hidden[-2], hidden[-1]], dim=1)  # (B, hidden*2)

        # Attention
        context = self.attention(hidden_last, lstm_out)

        # Combine
        combined = torch.cat([hidden_last, context], dim=1)
        logits = self.classifier(combined)
        return logits

    def predict(self, seq: KeystrokeSequence) -> BiometricResult:
        """Prédiction sur une séquence de frappe."""
        with torch.no_grad():
            # Build features
            features = np.column_stack([
                seq.key_codes / 255.0,  # normalize
                seq.durations / 1000.0,  # normalize to seconds
                seq.intervals / 1000.0,
                np.gradient(seq.durations) / 500.0,  # velocity
            ])
            x = torch.from_numpy(features).float().unsqueeze(0)

            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return BiometricResult(
            score=score,
            is_anomaly=score > 0.5,
            confidence=confidence,
            analysis_type="keystroke",
            model_name="KeystrokeRNNAttention",
            explanation=f"Keystroke analysis: anomaly_prob={score:.4f}",
            metadata={"n_keys": seq.n_keys},
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "KeystrokeRNNAttention",
            "hidden_dim": self.lstm.hidden_size,
            "n_layers": self.lstm.num_layers,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: MOUSE DYNAMICS (CNN + LSTM)
# ═══════════════════════════════════════════════════════════════════════════

class MouseCNN(nn.Module):
    """CNN pour extraction de features de trajectoire de souris."""

    def __init__(self, in_channels: int = 4, out_dim: int = 128):
        super().__init__()
        self.conv1 = nn.Conv1d(in_channels, 32, kernel_size=5, padding=2)
        self.bn1 = nn.BatchNorm1d(32)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=5, padding=2)
        self.bn2 = nn.BatchNorm1d(64)
        self.conv3 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(128)
        self.pool = nn.AdaptiveAvgPool1d(out_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, C, T)
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = F.relu(self.bn3(self.conv3(x)))
        x = self.pool(x)
        return x


class MouseCNNLSTM(nn.Module):
    """
    Mouse Dynamics avec CNN + LSTM.
    Analyse les mouvements de souris pour la vérification d'identité.
    """

    def __init__(
        self,
        input_dim: int = 4,  # x, y, velocity, acceleration
        cnn_dim: int = 128,
        hidden_dim: int = 128,
        n_layers: int = 2,
        n_classes: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.cnn = MouseCNN(input_dim, cnn_dim)

        self.lstm = nn.LSTM(
            cnn_dim, hidden_dim, n_layers,
            batch_first=True, bidirectional=True,
            dropout=dropout if n_layers > 1 else 0,
        )

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, C) — séquence de trajectoires
        B, T, C = x.shape

        # Process each segment with CNN
        x = x.transpose(1, 2)  # (B, C, T)
        cnn_out = self.cnn(x)  # (B, 128, cnn_dim)
        cnn_out = cnn_out.transpose(1, 2)  # (B, cnn_dim, 128)

        # LSTM
        lstm_out, (hidden, cell) = self.lstm(cnn_out)
        hidden_last = torch.cat([hidden[-2], hidden[-1]], dim=1)

        logits = self.classifier(hidden_last)
        return logits

    def predict(self, trajectory: MouseTrajectory) -> BiometricResult:
        """Prédiction sur une trajectoire de souris."""
        with torch.no_grad():
            # Compute velocity and acceleration if not provided
            vel = trajectory.velocity
            acc = trajectory.acceleration
            if vel is None:
                vel = np.gradient(np.sqrt(trajectory.x**2 + trajectory.y**2))
            if acc is None:
                acc = np.gradient(vel)

            features = np.column_stack([
                trajectory.x / 1920.0,  # normalize to screen
                trajectory.y / 1080.0,
                vel / 1000.0,
                acc / 500.0,
            ])
            x = torch.from_numpy(features).float().unsqueeze(0)

            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return BiometricResult(
            score=score,
            is_anomaly=score > 0.5,
            confidence=confidence,
            analysis_type="mouse",
            model_name="MouseCNNLSTM",
            explanation=f"Mouse dynamics analysis: anomaly_prob={score:.4f}",
            metadata={
                "n_points": len(trajectory.x),
                "path_length": float(np.sum(np.sqrt(np.diff(trajectory.x)**2 + np.diff(trajectory.y)**2))),
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "MouseCNNLSTM",
            "cnn_dim": self.cnn.pool.output_size,
            "hidden_dim": self.lstm.hidden_size,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: GAIT RECOGNITION (Skeleton-based GNN)
# ═══════════════════════════════════════════════════════════════════════════

class SkeletonGCNLayer(nn.Module):
    """Graph Convolution layer for skeleton data."""

    def __init__(self, in_dim: int, out_dim: int, adjacency: torch.Tensor, dropout: float = 0.1):
        super().__init__()
        self.adjacency = nn.Parameter(adjacency, requires_grad=False)
        self.W = nn.Linear(in_dim, out_dim)
        self.W_self = nn.Linear(in_dim, out_dim)
        self.bn = nn.BatchNorm1d(out_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, J, in_dim)
        # Message passing
        neighbor_feats = torch.einsum('ij,bjd->bid', self.adjacency, x)
        out = self.W(neighbor_feats) + self.W_self(x)
        out = out.transpose(1, 2)
        out = self.bn(out)
        out = out.transpose(1, 2)
        out = F.relu(out)
        out = self.dropout(out)
        return out


class SkeletonGNN(nn.Module):
    """
    Skeleton-based Graph Neural Network pour reconnaissance de démarche.
    Utilise la structure naturelle du squelette humain comme graphe.
    """

    # COCO skeleton adjacency (17 keypoints)
    SKELETON_ADJACENCY = [
        (0, 1), (0, 2), (1, 3), (2, 4),  # head
        (5, 6), (5, 7), (7, 9), (6, 8), (8, 10),  # arms
        (5, 11), (6, 12), (11, 13), (13, 15), (12, 14), (14, 16),  # legs
        (11, 12),  # hips
    ]

    def __init__(
        self,
        n_joints: int = 17,
        joint_dim: int = 3,  # x, y, confidence
        hidden_dim: int = 128,
        n_layers: int = 4,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()

        # Build adjacency matrix
        adj = torch.zeros((n_joints, n_joints))
        for i, j in self.SKELETON_ADJACENCY:
            adj[i, j] = 1.0
            adj[j, i] = 1.0
        # Normalize
        adj = adj / (adj.sum(dim=1, keepdim=True) + 1e-8)

        self.input_proj = nn.Linear(joint_dim, hidden_dim)

        self.gcn_layers = nn.ModuleList([
            SkeletonGCNLayer(hidden_dim, hidden_dim, adj, dropout)
            for _ in range(n_layers)
        ])

        self.temporal_conv = nn.Conv1d(hidden_dim, hidden_dim, kernel_size=3, padding=1)

        self.global_pool = nn.AdaptiveAvgPool1d(1)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, J, joint_dim) — séquence temporelle de poses
        B, T, J, D = x.shape

        # Process each timestep
        x = x.view(B * T, J, D)
        x = self.input_proj(x)

        for gcn in self.gcn_layers:
            x = gcn(x)

        x = x.view(B, T, J, -1)
        x = x.mean(dim=2)  # (B, T, hidden_dim) — pool over joints

        # Temporal convolution
        x = x.transpose(1, 2)  # (B, hidden_dim, T)
        x = self.temporal_conv(x)
        x = F.relu(x)

        # Global pooling
        x = self.global_pool(x).squeeze(-1)  # (B, hidden_dim)

        logits = self.classifier(x)
        return logits

    def predict(self, poses: List[SkeletonPose]) -> BiometricResult:
        """Prédiction sur une séquence de poses."""
        with torch.no_grad():
            # Build tensor
            T = len(poses)
            J = poses[0].n_joints
            features = np.zeros((T, J, 3))
            for t, pose in enumerate(poses):
                features[t] = pose.keypoints[:, :3]

            x = torch.from_numpy(features).float().unsqueeze(0)

            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return BiometricResult(
            score=score,
            is_anomaly=score > 0.5,
            confidence=confidence,
            analysis_type="gait",
            model_name="SkeletonGNN",
            explanation=f"Gait analysis: anomaly_prob={score:.4f}",
            metadata={"n_frames": T, "n_joints": J},
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "SkeletonGNN",
            "n_layers": len(self.gcn_layers),
            "hidden_dim": self.input_proj.out_features,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: BEHAVIORAL EMBEDDINGS (Contrastive Learning)
# ═══════════════════════════════════════════════════════════════════════════

class BehavioralEncoder(nn.Module):
    """Encoder pour embeddings comportementaux."""

    def __init__(self, input_dim: int, hidden_dim: int = 256, proj_dim: int = 128):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
        )
        self.projection = nn.Sequential(
            nn.Linear(hidden_dim // 2, proj_dim),
            nn.BatchNorm1d(proj_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.encoder(x)
        z = self.projection(h)
        return F.normalize(z, dim=1)


class BehavioralContrastive(nn.Module):
    """
    Behavioral Embeddings avec Contrastive Learning (SimCLR-style).
    Apprend des embeddings distincts pour chaque utilisateur.
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 256,
        proj_dim: int = 128,
        temperature: float = 0.07,
        memory_size: int = 4096,
    ):
        super().__init__()
        self.temperature = temperature
        self.memory_size = memory_size

        self.encoder = BehavioralEncoder(input_dim, hidden_dim, proj_dim)

        # Memory bank for known users
        self.register_buffer("memory", torch.randn(proj_dim, memory_size))
        self.memory = F.normalize(self.memory, dim=0)
        self.register_buffer("memory_ptr", torch.zeros(1, dtype=torch.long))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode behavioral features."""
        return self.encoder(x)

    def contrastive_loss(
        self, z1: torch.Tensor, z2: torch.Tensor
    ) -> torch.Tensor:
        """Compute NT-Xent loss for contrastive learning."""
        # z1, z2: (B, proj_dim) — two augmented views
        batch_size = z1.shape[0]

        # Positive pairs
        l_pos = torch.einsum('nc,nc->n', z1, z2).unsqueeze(-1)  # (B, 1)

        # Negative pairs (from memory)
        l_neg = torch.einsum('nc,ck->nk', z1, self.memory.clone().detach())  # (B, K)

        logits = torch.cat([l_pos, l_neg], dim=1) / self.temperature
        labels = torch.zeros(batch_size, dtype=torch.long, device=logits.device)

        loss = F.cross_entropy(logits, labels)

        # Update memory
        self._update_memory(z2)

        return loss

    @torch.no_grad()
    def _update_memory(self, keys: torch.Tensor):
        batch_size = keys.shape[0]
        ptr = int(self.memory_ptr)
        end_ptr = ptr + batch_size

        if end_ptr <= self.memory_size:
            self.memory[:, ptr:end_ptr] = keys.T
        else:
            # Wrap around
            remaining = self.memory_size - ptr
            self.memory[:, ptr:] = keys[:remaining].T
            self.memory[:, :batch_size - remaining] = keys[remaining:].T

        self.memory_ptr[0] = (ptr + batch_size) % self.memory_size

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode behavioral data into embedding."""
        with torch.no_grad():
            z = self.encoder(x)
        return z

    def compute_similarity(
        self, x1: torch.Tensor, x2: torch.Tensor
    ) -> float:
        """Compute cosine similarity between two behavioral samples."""
        z1 = self.encode(x1)
        z2 = self.encode(x2)
        sim = F.cosine_similarity(z1, z2, dim=1)
        return float(sim.mean().item())

    def predict(
        self, x: torch.Tensor, user_embedding: torch.Tensor
    ) -> BiometricResult:
        """Vérification d'identité par similarité comportementale."""
        z = self.encode(x)
        sim = F.cosine_similarity(z, user_embedding, dim=1)
        score = 1.0 - float(sim.mean().item())

        return BiometricResult(
            score=score,
            is_anomaly=score > 0.5,
            confidence=1.0 - abs(score - 0.5) * 2,
            analysis_type="behavioral",
            model_name="BehavioralContrastive",
            explanation=f"Behavioral verification: similarity={1-score:.4f}, anomaly_score={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "BehavioralContrastive",
            "proj_dim": self.encoder.projection[0].out_features,
            "memory_size": self.memory_size,
            "temperature": self.temperature,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# BIOMETRICS ENSEMBLE
# ═══════════════════════════════════════════════════════════════════════════

class BiometricsEnsemble:
    """
    Ensemble biométrique qui combine tous les analyseurs.
    Utilise un vote pondéré pour la décision finale.
    """

    def __init__(
        self,
        models: Dict[str, nn.Module],
        weights: Optional[Dict[str, float]] = None,
    ):
        self.models = models
        self.weights = weights or {
            name: 1.0 / len(models)
            for name in models
        }
        self.history: List[Dict[str, Any]] = []
        logger.info(
            "biometrics_ensemble_initialized",
            n_models=len(models),
            weights=self.weights,
        )

    def analyze_keystroke(self, seq: KeystrokeSequence) -> BiometricResult:
        """Analyse une séquence de frappe."""
        results = []
        if "keystroke" in self.models:
            r = self.models["keystroke"].predict(seq)
            results.append(r)
        return self._combine_results(results, "keystroke")

    def analyze_mouse(self, trajectory: MouseTrajectory) -> BiometricResult:
        """Analyse une trajectoire de souris."""
        results = []
        if "mouse" in self.models:
            r = self.models["mouse"].predict(trajectory)
            results.append(r)
        return self._combine_results(results, "mouse")

    def analyze_gait(self, poses: List[SkeletonPose]) -> BiometricResult:
        """Analyse une séquence de démarche."""
        results = []
        if "gait" in self.models:
            r = self.models["gait"].predict(poses)
            results.append(r)
        return self._combine_results(results, "gait")

    def analyze_behavioral(
        self, x: torch.Tensor, user_embedding: torch.Tensor
    ) -> BiometricResult:
        """Analyse comportementale."""
        results = []
        if "behavioral" in self.models:
            r = self.models["behavioral"].predict(x, user_embedding)
            results.append(r)
        return self._combine_results(results, "behavioral")

    def _combine_results(
        self, results: List[BiometricResult], analysis_type: str
    ) -> BiometricResult:
        """Combine les résultats pondérés."""
        if not results:
            return BiometricResult(
                score=0.0,
                is_anomaly=False,
                confidence=0.0,
                analysis_type=analysis_type,
                model_name="ensemble_empty",
            )

        weighted_score = 0.0
        total_weight = 0.0
        explanations = []

        for r in results:
            w = self.weights.get(r.model_name, 1.0 / len(results))
            weighted_score += w * r.score
            total_weight += w
            explanations.append(f"{r.model_name}: {r.score:.4f}")

        final_score = weighted_score / total_weight if total_weight > 0 else 0.0
        avg_confidence = np.mean([r.confidence for r in results])

        result = BiometricResult(
            score=final_score,
            is_anomaly=final_score > 0.5,
            confidence=avg_confidence,
            analysis_type=analysis_type,
            model_name="biometrics_ensemble",
            explanation=" | ".join(explanations),
            metadata={
                "n_models": len(results),
                "individual_scores": {r.model_name: r.score for r in results},
            },
        )

        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })

        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "n_models": len(self.models),
            "weights": self.weights,
            "n_analyses": len(self.history),
            "models": {
                name: model.get_stats() if hasattr(model, 'get_stats') else {}
                for name, model in self.models.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_ultra_biometrics(
    keystroke_dim: int = 128,
    mouse_dim: int = 128,
    gait_dim: int = 128,
    behavioral_dim: int = 64,
    device: str = "cpu",
    use_keystroke: bool = True,
    use_mouse: bool = True,
    use_gait: bool = True,
    use_behavioral: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système biométrique complet Niveau 9.

    Args:
        keystroke_dim: Dimension cachée pour keystroke
        mouse_dim: Dimension cachée pour souris
        gait_dim: Dimension cachée pour démarche
        behavioral_dim: Dimension d'entrée pour embeddings comportementaux
        device: "cpu" ou "cuda"
        use_keystroke: Activer KeystrokeRNNAttention
        use_mouse: Activer MouseCNNLSTM
        use_gait: Activer SkeletonGNN
        use_behavioral: Activer BehavioralContrastive

    Returns:
        Dict avec tous les composants
    """
    models = {}

    if use_keystroke:
        models["keystroke"] = KeystrokeRNNAttention(hidden_dim=keystroke_dim)
        logger.info("✅ KeystrokeRNNAttention initialized")

    if use_mouse:
        models["mouse"] = MouseCNNLSTM(hidden_dim=mouse_dim)
        logger.info("✅ MouseCNNLSTM initialized")

    if use_gait:
        models["gait"] = SkeletonGNN(hidden_dim=gait_dim)
        logger.info("✅ SkeletonGNN initialized")

    if use_behavioral:
        models["behavioral"] = BehavioralContrastive(input_dim=behavioral_dim)
        logger.info("✅ BehavioralContrastive initialized")

    ensemble = BiometricsEnsemble(models=models)
    logger.info("✅ BiometricsEnsemble initialized")

    return {
        "models": models,
        "ensemble": ensemble,
        "config": {
            "keystroke_dim": keystroke_dim,
            "mouse_dim": mouse_dim,
            "gait_dim": gait_dim,
            "behavioral_dim": behavioral_dim,
            "device": device,
            "n_models": len(models),
        },
    }


def create_ultra_biometrics_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_biometrics(
        use_keystroke=True,
        use_mouse=False,
        use_gait=False,
        use_behavioral=False,
    )


def create_ultra_biometrics_full() -> Dict[str, Any]:
    """Version complète avec tous les analyseurs."""
    return create_ultra_biometrics(
        use_keystroke=True,
        use_mouse=True,
        use_gait=True,
        use_behavioral=True,
    )


# Instance globale
ultra_biometrics_system = create_ultra_biometrics_full()


def get_ultra_biometrics() -> Dict[str, Any]:
    """Get the global biometrics system instance."""
    return ultra_biometrics_system
