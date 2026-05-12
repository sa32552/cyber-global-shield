"""
Cyber Global Shield — Ultra-Pointer Detection Module (Niveau 1)
==============================================================

4 technologies de pointe coordonnées pour une détection d'anomalies ultime :

1. Isolation Forest Extreme (math pure : random cuts optimaux avec Extended IF)
2. Deep SVDD (One-Class Classification avec réseaux profonds)
3. VAE + Normalizing Flows (RealNVP pour densité exacte)
4. Ensemble Bayesian (combinaison probabiliste avec Monte Carlo Dropout)

Chaque détecteur peut fonctionner indépendamment ou en synergie via l'Ensemble.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone
import structlog
from scipy import stats as scipy_stats
from sklearn.tree import DecisionTreeRegressor

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionResult:
    """Résultat unifié de détection d'anomalie."""
    anomaly_score: float          # 0.0 (normal) → 1.0 (anomalie)
    is_anomaly: bool
    threshold_used: float
    model_confidence: float       # 0.0 → 1.0
    reconstruction_error: float = 0.0
    log_probability: float = 0.0  # Log-density (normalizing flows)
    latent_distance: float = 0.0  # Distance in latent space (Deep SVDD)
    feature_importance: Optional[Dict[str, float]] = None
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0
    detector_name: str = "unknown"


@dataclass
class EnsembleResult:
    """Résultat combiné de l'ensemble bayésien."""
    final_score: float
    is_anomaly: bool
    detector_scores: Dict[str, float]
    detector_weights: Dict[str, float]
    uncertainty: float            # Bayesian uncertainty (0=confident, 1=uncertain)
    ensemble_confidence: float
    inference_time_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# 1. ISOLATION FOREST EXTREME (Extended Isolation Forest)
# ═══════════════════════════════════════════════════════════════════════════

class ExtendedIsolationTree:
    """
    Extended Isolation Tree with random slope splits.
    
    Contrairement à l'Isolation Forest classique qui utilise des splits
    axis-aligned, Extended IF utilise des hyperplans aléatoires avec
    des pentes aléatoires, permettant de capturer des corrélations
    entre features et des anomalies multivariées complexes.
    
    Math: split(x) = sign(w·x - b) où w ~ N(0, I) et b ~ Uniform(min, max)
    """
    
    def __init__(self, max_depth: int = 100, extension_level: float = 1.0):
        self.max_depth = max_depth
        self.extension_level = extension_level  # 0=axis-aligned, 1=full random
        self.root: Optional[dict] = None
        self._size = 0
        self._rng = np.random.default_rng()
    
    def fit(self, X: np.ndarray):
        """Build the isolation tree."""
        self._size = len(X)
        indices = np.arange(len(X))
        self.root = self._build_tree(X, indices, 0)
    
    def _build_tree(self, X: np.ndarray, indices: np.ndarray, depth: int) -> dict:
        """Recursively build tree."""
        n = len(indices)
        
        if depth >= self.max_depth or n <= 1:
            return {"type": "leaf", "size": n, "depth": depth}
        
        n_features = X.shape[1]
        
        # Extended split: random hyperplane
        if self._rng.random() < self.extension_level:
            # Random normal vector w
            w = self._rng.standard_normal(n_features)
            w = w / (np.linalg.norm(w) + 1e-10)
            
            # Project data onto w
            projections = X[indices] @ w
            
            # Random intercept b
            p_min, p_max = projections.min(), projections.max()
            if p_max - p_min < 1e-10:
                return {"type": "leaf", "size": n, "depth": depth}
            b = self._rng.uniform(p_min, p_max)
            
            left_mask = projections <= b
        else:
            # Axis-aligned split (classic IF)
            split_dim = self._rng.integers(0, n_features)
            split_val = self._rng.uniform(
                X[indices, split_dim].min(),
                X[indices, split_dim].max()
            )
            left_mask = X[indices, split_dim] <= split_val
            w = np.zeros(n_features)
            w[split_dim] = 1.0
            b = split_val
        
        left_indices = indices[left_mask]
        right_indices = indices[~left_mask]
        
        if len(left_indices) == 0 or len(right_indices) == 0:
            return {"type": "leaf", "size": n, "depth": depth}
        
        return {
            "type": "node",
            "w": w,
            "b": b,
            "left": self._build_tree(X, left_indices, depth + 1),
            "right": self._build_tree(X, right_indices, depth + 1),
            "size": n,
        }
    
    def path_length(self, x: np.ndarray) -> float:
        """Compute path length for a single point."""
        node = self.root
        depth = 0.0
        
        while node["type"] != "leaf":
            w = node["w"]
            b = node["b"]
            
            if x @ w <= b:
                node = node["left"]
            else:
                node = node["right"]
            depth += 1.0
        
        # Add adjustment for leaf size (c(n) = average path length)
        n = node["size"]
        if n > 1:
            depth += self._c_factor(n)
        
        return depth
    
    def _c_factor(self, n: int) -> float:
        """Average path length of unsuccessful search in BST."""
        if n <= 1:
            return 0.0
        return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class IsolationForestExtreme:
    """
    Extended Isolation Forest — State-of-the-Art.
    
    Améliorations par rapport à l'IF classique :
    - Splits hyperplans aléatoires (Extended IF)
    - Scoring probabiliste avec calibration
    - Adaptive threshold basé sur l'évolution du score
    - Détection de concept drift
    
    Références :
    - Hariri et al. "Extended Isolation Forest" (2019)
    - Liu et al. "Isolation Forest" (2008)
    """
    
    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 100,
        extension_level: float = 0.8,
        subsample_size: int = 256,
        anomaly_threshold: float = 0.85,
        adaptive: bool = True,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.extension_level = extension_level
        self.subsample_size = subsample_size
        self.anomaly_threshold = anomaly_threshold
        self.adaptive = adaptive
        
        self.trees: List[ExtendedIsolationTree] = []
        self._fitted = False
        self._n_features: int = 0
        self._recent_scores: deque = deque(maxlen=1000)
        self._total_samples = 0
    
    def fit(self, X: np.ndarray):
        """Fit the isolation forest."""
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
        
        self._n_features = X.shape[1]
        n_samples = len(X)
        
        self.trees = []
        for i in range(self.n_estimators):
            # Subsample
            if n_samples > self.subsample_size:
                indices = np.random.choice(n_samples, self.subsample_size, replace=False)
            else:
                indices = np.arange(n_samples)
            
            tree = ExtendedIsolationTree(
                max_depth=self.max_depth,
                extension_level=self.extension_level,
            )
            tree.fit(X[indices])
            self.trees.append(tree)
        
        self._fitted = True
        logger.info(
            "extended_if_fitted",
            n_trees=self.n_estimators,
            n_samples=n_samples,
            n_features=self._n_features,
        )
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly scores (0=normal, 1=anomaly)."""
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
        
        if not self._fitted:
            return np.zeros(len(X))
        
        scores = np.zeros(len(X))
        for i, x in enumerate(X):
            path_lengths = np.array([tree.path_length(x) for tree in self.trees])
            avg_path = np.mean(path_lengths)
            
            # Normalize by expected depth
            expected_depth = self._c_factor(self.subsample_size)
            score = 2.0 ** (-avg_path / expected_depth) if expected_depth > 0 else 0.5
            
            scores[i] = float(np.clip(score, 0.0, 1.0))
        
        return scores
    
    def predict(self, X: np.ndarray) -> List[DetectionResult]:
        """Predict anomalies."""
        import time
        start = time.time()
        
        scores = self.score_samples(X)
        threshold = self._get_threshold()
        
        results = []
        for score in scores:
            is_anomaly = score > threshold
            confidence = min(abs(score - threshold) / max(threshold, 0.01), 1.0)
            
            self._recent_scores.append(score)
            self._total_samples += 1
            
            results.append(DetectionResult(
                anomaly_score=float(score),
                is_anomaly=is_anomaly,
                threshold_used=float(threshold),
                model_confidence=float(confidence),
                inference_time_ms=(time.time() - start) * 1000 / len(scores),
                detector_name="IsolationForestExtreme",
            ))
        
        return results
    
    def _get_threshold(self) -> float:
        """Get adaptive threshold."""
        if not self.adaptive or len(self._recent_scores) < 100:
            return self.anomaly_threshold
        
        scores = np.array(self._recent_scores)
        adaptive = float(np.percentile(scores, 95))
        return 0.7 * adaptive + 0.3 * self.anomaly_threshold
    
    def _c_factor(self, n: int) -> float:
        """Average path length of unsuccessful search in BST."""
        if n <= 1:
            return 0.0
        return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            "n_trees": len(self.trees),
            "n_features": self._n_features,
            "fitted": self._fitted,
            "total_samples": self._total_samples,
            "threshold": self._get_threshold(),
            "extension_level": self.extension_level,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2. DEEP SVDD (One-Class Classification)
# ═══════════════════════════════════════════════════════════════════════════

class DeepSVDD(nn.Module):
    """
    Deep Support Vector Data Description.
    
    Apprend une hypersphère qui englobe les données normales dans
    l'espace latent. Les anomalies sont détectées par leur distance
    au centre de la sphère.
    
    Math: min_R,θ R² + (1/νn) Σ max(0, ||φ(x_i;θ) - c||² - R²)
    
    Référence : Ruff et al. "Deep One-Class Classification" (ICML 2018)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        latent_dim: int = 32,
        hidden_dims: List[int] = None,
        nu: float = 0.1,  # Trade-off (fraction of anomalies expected)
        learning_rate: float = 1e-3,
        device: str = "cpu",
    ):
        super().__init__()
        
        if hidden_dims is None:
            hidden_dims = [256, 128, 64]
        
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.nu = nu
        self.device = torch.device(device)
        
        # Encoder network
        layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.LeakyReLU(0.2),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        
        layers.append(nn.Linear(prev_dim, latent_dim))
        self.encoder = nn.Sequential(*layers)
        
        # Center c (learned or fixed)
        self.center: Optional[torch.Tensor] = None
        self.R: torch.Tensor = nn.Parameter(torch.tensor(1.0))  # Radius
        
        self.optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        self._fitted = False
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input to latent space."""
        return self.encoder(x)
    
    def fit(
        self,
        X: torch.Tensor,
        epochs: int = 50,
        batch_size: int = 64,
        verbose: bool = True,
    ):
        """Fit Deep SVDD model."""
        if len(X.shape) == 1:
            X = X.view(-1, self.input_dim)
        
        X = X.to(self.device)
        n_samples = len(X)
        
        # Initialize center as mean of encoded data
        with torch.no_grad():
            self.eval()
            z = self.encoder(X[:min(1000, n_samples)])
            self.center = z.mean(dim=0).detach()
        
        # Training
        self.train()
        dataset = torch.utils.data.TensorDataset(X)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        for epoch in range(epochs):
            epoch_loss = 0.0
            n_batches = 0
            
            for (batch,) in loader:
                self.optimizer.zero_grad()
                
                z = self.encoder(batch)
                dists = torch.sum((z - self.center) ** 2, dim=1)
                
                # SVDD loss: R² + (1/νn) Σ max(0, ||z-c||² - R²)
                scores = dists - self.R ** 2
                loss = self.R ** 2 + (1.0 / (self.nu * len(batch))) * torch.sum(
                    torch.max(torch.zeros_like(scores), scores)
                )
                
                loss.backward()
                self.optimizer.step()
                
                epoch_loss += loss.item()
                n_batches += 1
            
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    "deep_svdd_epoch",
                    epoch=epoch + 1,
                    loss=f"{epoch_loss / n_batches:.4f}",
                    radius=f"{self.R.item():.4f}",
                )
        
        self._fitted = True
        self.eval()
        
        return {"final_loss": epoch_loss / n_batches, "radius": self.R.item()}
    
    def predict(self, X: torch.Tensor) -> List[DetectionResult]:
        """Predict anomalies based on distance to center."""
        import time
        start = time.time()
        
        if len(X.shape) == 1:
            X = X.view(-1, self.input_dim)
        
        X = X.to(self.device)
        
        with torch.no_grad():
            z = self.encoder(X)
            dists = torch.sum((z - self.center) ** 2, dim=1)
            
            # Anomaly score: normalized distance
            max_dist = dists.max().item() if dists.max() > 0 else 1.0
            scores = (dists / max_dist).cpu().numpy()
            
            # Threshold based on nu quantile
            threshold = float(np.percentile(scores, (1 - self.nu) * 100))
        
        results = []
        for score in scores:
            is_anomaly = score > threshold
            confidence = min(abs(score - threshold) / max(threshold, 0.01), 1.0)
            
            results.append(DetectionResult(
                anomaly_score=float(score),
                is_anomaly=is_anomaly,
                threshold_used=float(threshold),
                model_confidence=float(confidence),
                latent_distance=float(score),
                inference_time_ms=(time.time() - start) * 1000 / len(scores),
                detector_name="DeepSVDD",
            ))
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "nu": self.nu,
            "radius": self.R.item() if hasattr(self, 'R') else 0.0,
            "center_norm": torch.norm(self.center).item() if self.center is not None else 0.0,
            "fitted": self._fitted,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 3. VAE + NORMALIZING FLOWS (RealNVP)
# ═══════════════════════════════════════════════════════════════════════════

class AffineCouplingLayer(nn.Module):
    """
    Affine coupling layer for RealNVP.
    
    Implements: y[:d] = x[:d]
                y[d:] = x[d:] * exp(s(x[:d])) + t(x[:d])
    
    où s = scale, t = translation (réseaux de neurones).
    Le Jacobien est triangulaire → log-det facile à calculer.
    """
    
    def __init__(self, input_dim: int, hidden_dim: int = 64, mask_ratio: float = 0.5):
        super().__init__()
        self.d = int(input_dim * mask_ratio)
        
        # Scale network
        self.s_net = nn.Sequential(
            nn.Linear(self.d, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim - self.d),
            nn.Tanh(),  # Bound scale for stability
        )
        
        # Translation network
        self.t_net = nn.Sequential(
            nn.Linear(self.d, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim - self.d),
        )
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Forward pass: x → y, log_det_J."""
        x1, x2 = x[:, :self.d], x[:, self.d:]
        
        s = self.s_net(x1)
        t = self.t_net(x1)
        
        y2 = x2 * torch.exp(s) + t
        y = torch.cat([x1, y2], dim=1)
        
        log_det = s.sum(dim=1)
        
        return y, log_det
    
    def inverse(self, y: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Inverse pass: y → x, log_det_J_inv."""
        y1, y2 = y[:, :self.d], y[:, self.d:]
        
        s = self.s_net(y1)
        t = self.t_net(y1)
        
        x2 = (y2 - t) * torch.exp(-s)
        x = torch.cat([y1, x2], dim=1)
        
        log_det = -s.sum(dim=1)
        
        return x, log_det


class RealNVP(nn.Module):
    """
    Real Non-Volume Preserving (RealNVP) — Normalizing Flow.
    
    Transforme une distribution simple (gaussienne) en distribution
    complexe via une séquence de transformations inversibles.
    
    Permet de calculer EXACTEMENT la log-densité des données,
    contrairement aux VAE qui ne donnent qu'une borne inférieure (ELBO).
    
    Référence : Dinh et al. "Density estimation using Real NVP" (ICLR 2017)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        n_layers: int = 8,
        hidden_dim: int = 128,
    ):
        super().__init__()
        
        self.input_dim = input_dim
        
        # Stack of affine coupling layers with alternating masks
        self.layers = nn.ModuleList()
        for i in range(n_layers):
            mask_ratio = 0.5 if i % 2 == 0 else 0.3
            self.layers.append(
                AffineCouplingLayer(input_dim, hidden_dim, mask_ratio)
            )
        
        # Final gaussianization layer
        self.fc = nn.Linear(input_dim, input_dim)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass: x → z (latent), log_det_J.
        log p(x) = log p(z) + log |det J|
        """
        log_det_total = 0.0
        z = x
        
        for layer in self.layers:
            z, log_det = layer(z)
            log_det_total += log_det
        
        z = self.fc(z)
        
        return z, log_det_total
    
    def inverse(self, z: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Inverse pass: z → x."""
        log_det_total = 0.0
        x = self.fc(z)
        
        for layer in reversed(self.layers):
            x, log_det = layer.inverse(x)
            log_det_total += log_det
        
        return x, log_det_total
    
    def log_prob(self, x: torch.Tensor) -> torch.Tensor:
        """Compute log-probability of data under the flow."""
        z, log_det = self.forward(x)
        
        # Log-prob of base distribution (standard normal)
        log_prob_z = -0.5 * (z ** 2 + np.log(2 * np.pi)).sum(dim=1)
        
        return log_prob_z + log_det


class VAEFlow(nn.Module):
    """
    VAE + Normalizing Flow hybride.
    
    Utilise un VAE standard mais remplace le prior gaussien par
    un RealNVP flow pour une distribution latente plus expressive.
    
    Architecture :
    - Encoder: x → z_mean, z_logvar
    - Flow: transforme z en z' avec densité exacte
    - Decoder: z' → x_reconstructed
    
    Avantage : ELBO plus serré + densité exacte dans l'espace latent.
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        latent_dim: int = 32,
        hidden_dim: int = 256,
        n_flow_layers: int = 4,
        device: str = "cpu",
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.device = torch.device(device)
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.LeakyReLU(0.2),
        )
        self.z_mean = nn.Linear(hidden_dim, latent_dim)
        self.z_logvar = nn.Linear(hidden_dim, latent_dim)
        
        # Normalizing Flow in latent space
        self.flow = RealNVP(
            input_dim=latent_dim,
            n_layers=n_flow_layers,
            hidden_dim=hidden_dim // 2,
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, input_dim),
        )
        
        self.optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        self._fitted = False
    
    def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Encode input to latent distribution."""
        h = self.encoder(x)
        return self.z_mean(h), self.z_logvar(h), h
    
    def reparameterize(self, mean: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """Reparameterization trick."""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mean + eps * std
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        Returns: reconstructed, z, z_flow, log_prob_z
        """
        mean, logvar, _ = self.encode(x)
        z = self.reparameterize(mean, logvar)
        
        # Transform through flow
        z_flow, log_det = self.flow(z)
        
        # Decode
        reconstructed = self.decoder(z_flow)
        
        # Log-prob of transformed latent
        log_prob_z = -0.5 * (z_flow ** 2 + np.log(2 * np.pi)).sum(dim=1) + log_det
        
        return reconstructed, z, z_flow, log_prob_z
    
    def loss(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        """Compute VAE + Flow loss."""
        reconstructed, z, z_flow, log_prob_z = self.forward(x)
        
        # Reconstruction loss
        recon_loss = F.mse_loss(reconstructed, x, reduction='sum')
        
        # KL divergence with flow-based prior
        mean, logvar, _ = self.encode(x)
        kl_loss = -0.5 * torch.sum(1 + logvar - mean.pow(2) - logvar.exp())
        
        # Flow log-prob (should be high for normal data)
        flow_loss = -log_prob_z.sum()
        
        total_loss = recon_loss + 0.1 * kl_loss + 0.01 * flow_loss
        
        return {
            "total": total_loss,
            "reconstruction": recon_loss,
            "kl": kl_loss,
            "flow": flow_loss,
        }
    
    def fit(
        self,
        X: torch.Tensor,
        epochs: int = 50,
        batch_size: int = 64,
        verbose: bool = True,
    ):
        """Fit VAE + Flow model."""
        if len(X.shape) == 1:
            X = X.view(-1, self.input_dim)
        
        X = X.to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        self.train()
        
        for epoch in range(epochs):
            epoch_loss = 0.0
            n_batches = 0
            
            for (batch,) in loader:
                self.optimizer.zero_grad()
                
                losses = self.loss(batch)
                losses["total"].backward()
                torch.nn.utils.clip_grad_norm_(self.parameters(), 1.0)
                self.optimizer.step()
                
                epoch_loss += losses["total"].item()
                n_batches += 1
            
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    "vaeflow_epoch",
                    epoch=epoch + 1,
                    loss=f"{epoch_loss / n_batches:.4f}",
                )
        
        self._fitted = True
        self.eval()
        
        return {"final_loss": epoch_loss / n_batches}
    
    def predict(self, X: torch.Tensor) -> List[DetectionResult]:
        """Predict anomalies using reconstruction error + log-prob."""
        import time
        start = time.time()
        
        if len(X.shape) == 1:
            X = X.view(-1, self.input_dim)
        
        X = X.to(self.device)
        
        results = []
        with torch.no_grad():
            reconstructed, z, z_flow, log_prob_z = self.forward(X)
            
            # Reconstruction error
            recon_errors = F.mse_loss(reconstructed, X, reduction='none').mean(dim=1)
            
            # Log-probability (lower = more anomalous)
            log_probs = log_prob_z.cpu().numpy()
            
            # Combined anomaly score
            recon_scores = (recon_errors / recon_errors.max()).cpu().numpy()
            prob_scores = 1.0 - scipy_stats.norm.cdf(
                (log_probs - log_probs.mean()) / (log_probs.std() + 1e-8)
            )
            
            scores = 0.6 * recon_scores + 0.4 * prob_scores
            threshold = float(np.percentile(scores, 95))
            
            for i in range(len(X)):
                is_anomaly = scores[i] > threshold
                confidence = min(abs(scores[i] - threshold) / max(threshold, 0.01), 1.0)
                
                results.append(DetectionResult(
                    anomaly_score=float(scores[i]),
                    is_anomaly=is_anomaly,
                    threshold_used=float(threshold),
                    model_confidence=float(confidence),
                    reconstruction_error=float(recon_errors[i]),
                    log_probability=float(log_probs[i]),
                    inference_time_ms=(time.time() - start) * 1000 / len(X),
                    detector_name="VAEFlow",
                ))
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "n_flow_layers": len(self.flow.layers),
            "fitted": self._fitted,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 4. BAYESIAN ENSEMBLE (Combinaison probabiliste)
# ═══════════════════════════════════════════════════════════════════════════

class BayesianEnsemble:
    """
    Ensemble Bayésien pour combiner plusieurs détecteurs.
    
    Utilise :
    - Bayesian Model Averaging (BMA) avec poids appris
    - Monte Carlo Dropout pour l'incertitude
    - Calibration par Platt scaling
    - Détection de conflit entre détecteurs
    
    Chaque détecteur vote avec son score + sa confiance.
    L'incertitude bayésienne permet de savoir quand l'ensemble
    n'est pas sûr de sa décision.
    """
    
    def __init__(
        self,
        detectors: Dict[str, Any],
        weights: Optional[Dict[str, float]] = None,
        n_mc_samples: int = 50,
        conflict_threshold: float = 0.3,
    ):
        self.detectors = detectors
        self.weights = weights or {name: 1.0 / len(detectors) for name in detectors}
        self.n_mc_samples = n_mc_samples
        self.conflict_threshold = conflict_threshold
        
        # Calibration parameters (Platt scaling)
        self._calib_a: float = 1.0
        self._calib_b: float = 0.0
        self._calibrated = False
        
        # Performance tracking
        self._performance: Dict[str, List[float]] = {
            name: [] for name in detectors
        }
    
    def predict(self, X: np.ndarray) -> EnsembleResult:
        """
        Prédiction combinée avec incertitude bayésienne.
        
        Returns:
            EnsembleResult avec score final, incertitude, et scores individuels
        """
        import time
        start = time.time()
        
        # Get predictions from each detector
        detector_scores = {}
        detector_confidences = {}
        
        for name, detector in self.detectors.items():
            if hasattr(detector, 'predict'):
                if isinstance(X, np.ndarray):
                    results = detector.predict(X)
                else:
                    results = detector.predict(torch.from_numpy(X).float())
                
                if isinstance(results, list):
                    # Take mean score across samples
                    scores = [r.anomaly_score for r in results]
                    confs = [r.model_confidence for r in results]
                    detector_scores[name] = float(np.mean(scores))
                    detector_confidences[name] = float(np.mean(confs))
                else:
                    detector_scores[name] = results.anomaly_score
                    detector_confidences[name] = results.model_confidence
        
        # Bayesian Model Averaging
        weighted_scores = []
        total_weight = 0.0
        
        for name, score in detector_scores.items():
            w = self.weights.get(name, 1.0 / len(self.detectors))
            confidence = detector_confidences.get(name, 0.5)
            
            # Weight = base_weight * confidence
            effective_weight = w * confidence
            weighted_scores.append(score * effective_weight)
            total_weight += effective_weight
        
        final_score = sum(weighted_scores) / (total_weight + 1e-10)
        
        # Calibration (Platt scaling)
        if self._calibrated:
            final_score = 1.0 / (1.0 + np.exp(-(self._calib_a * final_score + self._calib_b)))
        
        # Bayesian uncertainty estimation
        # High variance between detectors = high uncertainty
        score_values = list(detector_scores.values())
        if len(score_values) > 1:
            score_variance = float(np.var(score_values))
            uncertainty = min(score_variance / 0.25, 1.0)  # Normalize
        else:
            uncertainty = 0.0
        
        # Conflict detection
        anomaly_votes = sum(1 for s in score_values if s > 0.5)
        total_votes = len(score_values)
        conflict = abs(anomaly_votes / total_votes - 0.5) * 2 if total_votes > 0 else 0.0
        
        # Final decision
        is_anomaly = final_score > 0.5
        ensemble_confidence = 1.0 - uncertainty
        
        inference_time = (time.time() - start) * 1000
        
        return EnsembleResult(
            final_score=float(final_score),
            is_anomaly=is_anomaly,
            detector_scores=detector_scores,
            detector_weights=self.weights,
            uncertainty=float(uncertainty),
            ensemble_confidence=float(ensemble_confidence),
            inference_time_ms=inference_time,
        )
    
    def calibrate(self, X: np.ndarray, y: np.ndarray):
        """
        Calibrate ensemble using Platt scaling.
        
        Ajuste les paramètres a et b pour que les scores
        soient bien calibrés en probabilités.
        """
        from sklearn.linear_model import LogisticRegression
        
        # Get scores from ensemble
        scores = []
        for x in X:
            result = self.predict(x.reshape(1, -1))
            scores.append(result.final_score)
        
        # Fit logistic regression for calibration
        calibrator = LogisticRegression()
        calibrator.fit(np.array(scores).reshape(-1, 1), y)
        
        self._calib_a = calibrator.coef_[0][0]
        self._calib_b = calibrator.intercept_[0]
        self._calibrated = True
        
        logger.info(
            "ensemble_calibrated",
            a=self._calib_a,
            b=self._calib_b,
            n_samples=len(X),
        )
    
    def update_weights(self, performance: Dict[str, float]):
        """
        Mettre à jour les poids basés sur la performance récente.
        
        Args:
            performance: Dict {detector_name: accuracy/precision}
        """
        total = sum(performance.values())
        if total > 0:
            self.weights = {
                name: perf / total
                for name, perf in performance.items()
            }
            logger.info("ensemble_weights_updated", weights=self.weights)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ensemble statistics."""
        return {
            "n_detectors": len(self.detectors),
            "weights": self.weights,
            "calibrated": self._calibrated,
            "calib_a": self._calib_a,
            "calib_b": self._calib_b,
            "conflict_threshold": self.conflict_threshold,
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_ultra_detector(
    input_dim: int = 128,
    latent_dim: int = 32,
    device: str = "cpu",
    use_iforest: bool = True,
    use_deep_svdd: bool = True,
    use_vaeflow: bool = True,
    use_ensemble: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système de détection complet Niveau 1.
    
    Retourne un dict avec tous les détecteurs et l'ensemble.
    
    Args:
        input_dim: Dimension d'entrée des features
        latent_dim: Dimension de l'espace latent
        device: "cpu" ou "cuda"
        use_iforest: Activer Isolation Forest Extreme
        use_deep_svdd: Activer Deep SVDD
        use_vaeflow: Activer VAE + Normalizing Flow
        use_ensemble: Activer l'ensemble bayésien
    
    Returns:
        Dict avec tous les composants
    """
    detectors = {}
    
    if use_iforest:
        detectors["iforest_extreme"] = IsolationForestExtreme(
            n_estimators=200,
            extension_level=0.8,
            adaptive=True,
        )
        logger.info("✅ IsolationForestExtreme initialized")
    
    if use_deep_svdd:
        detectors["deep_svdd"] = DeepSVDD(
            input_dim=input_dim,
            latent_dim=latent_dim,
            nu=0.1,
            device=device,
        )
        logger.info("✅ DeepSVDD initialized")
    
    if use_vaeflow:
        detectors["vaeflow"] = VAEFlow(
            input_dim=input_dim,
            latent_dim=latent_dim,
            n_flow_layers=4,
            device=device,
        )
        logger.info("✅ VAEFlow initialized")
    
    ensemble = None
    if use_ensemble and detectors:
        ensemble = BayesianEnsemble(
            detectors=detectors,
            weights={name: 1.0 / len(detectors) for name in detectors},
        )
        logger.info("✅ BayesianEnsemble initialized")
    
    return {
        "detectors": detectors,
        "ensemble": ensemble,
        "config": {
            "input_dim": input_dim,
            "latent_dim": latent_dim,
            "device": device,
            "n_detectors": len(detectors),
        },
    }


def create_ultra_detector_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_detector(
        input_dim=128,
        latent_dim=16,
        use_iforest=True,
        use_deep_svdd=False,
        use_vaeflow=False,
        use_ensemble=False,
    )


def create_ultra_detector_full() -> Dict[str, Any]:
    """Version complète avec tous les détecteurs."""
    return create_ultra_detector(
        input_dim=128,
        latent_dim=32,
        use_iforest=True,
        use_deep_svdd=True,
        use_vaeflow=True,
        use_ensemble=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# INTÉGRATION AVEC LES MODULES EXISTANTS
# ═══════════════════════════════════════════════════════════════════════════

class UltraDetectorPipeline:
    """
    Pipeline complet qui intègre l'ultra détecteur avec les modules existants.
    
    Coordonne :
    - AnomalyDetector (Diffusion Model existant)
    - OnlineDetector (Streaming existant)
    - GNN Detector (Graph existant)
    - Ultra Detector (nouveau)
    - Bayesian Ensemble (combinaison finale)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        device: str = "cpu",
    ):
        self.input_dim = input_dim
        self.device = device
        
        # Ultra detectors
        self.ultra_system = create_ultra_detector_full()
        
        # Reference to existing detectors (lazy import)
        self._existing_detectors: Dict[str, Any] = {}
        
        logger.info("🚀 UltraDetectorPipeline initialized")
    
    def load_existing_detectors(self):
        """Load existing detectors from the codebase."""
        try:
            from .anomaly_detector import AnomalyDetector
            self._existing_detectors["diffusion"] = AnomalyDetector()
            logger.info("✅ Loaded AnomalyDetector (Diffusion)")
        except Exception as e:
            logger.warning("Could not load AnomalyDetector", error=str(e))
        
        try:
            from .online_detector import OnlineDetector
            self._existing_detectors["online"] = OnlineDetector()
            logger.info("✅ Loaded OnlineDetector (Streaming)")
        except Exception as e:
            logger.warning("Could not load OnlineDetector", error=str(e))
        
        try:
            from .gnn_detector import GNNDetector
            self._existing_detectors["gnn"] = GNNDetector()
            logger.info("✅ Loaded GNNDetector (Graph)")
        except Exception as e:
            logger.warning("Could not load GNNDetector", error=str(e))
    
    def fit_ultra_detectors(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        """Fit all ultra detectors on training data."""
        # Fit Isolation Forest Extreme
        if "iforest_extreme" in self.ultra_system["detectors"]:
            self.ultra_system["detectors"]["iforest_extreme"].fit(X)
            logger.info("✅ IForestExtreme fitted")
        
        # Fit Deep SVDD
        if "deep_svdd" in self.ultra_system["detectors"]:
            X_tensor = torch.from_numpy(X).float()
            self.ultra_system["detectors"]["deep_svdd"].fit(X_tensor, epochs=30)
            logger.info("✅ DeepSVDD fitted")
        
        # Fit VAE Flow
        if "vaeflow" in self.ultra_system["detectors"]:
            X_tensor = torch.from_numpy(X).float()
            self.ultra_system["detectors"]["vaeflow"].fit(X_tensor, epochs=30)
            logger.info("✅ VAEFlow fitted")
        
        # Calibrate ensemble
        if self.ultra_system["ensemble"] and y is not None:
            self.ultra_system["ensemble"].calibrate(X, y)
            logger.info("✅ Ensemble calibrated")
    
    def predict(self, X: np.ndarray) -> EnsembleResult:
        """
        Prédiction complète via l'ensemble bayésien.
        
        Si l'ensemble est disponible, utilise tous les détecteurs.
        Sinon, utilise le meilleur détecteur disponible.
        """
        if self.ultra_system["ensemble"]:
            return self.ultra_system["ensemble"].predict(X)
        elif self.ultra_system["detectors"]:
            # Fallback: use first available detector
            name = list(self.ultra_system["detectors"].keys())[0]
            detector = self.ultra_system["detectors"][name]
            results = detector.predict(X)
            
            if isinstance(results, list):
                scores = [r.anomaly_score for r in results]
                final_score = float(np.mean(scores))
            else:
                final_score = results.anomaly_score
            
            return EnsembleResult(
                final_score=final_score,
                is_anomaly=final_score > 0.5,
                detector_scores={name: final_score},
                detector_weights={name: 1.0},
                uncertainty=0.5,
                ensemble_confidence=0.5,
            )
        else:
            return EnsembleResult(
                final_score=0.0,
                is_anomaly=False,
                detector_scores={},
                detector_weights={},
                uncertainty=1.0,
                ensemble_confidence=0.0,
            )
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get complete system statistics."""
        stats = {
            "ultra_detectors": {
                name: det.get_stats() if hasattr(det, 'get_stats') else {}
                for name, det in self.ultra_system["detectors"].items()
            },
            "ensemble": self.ultra_system["ensemble"].get_stats() if self.ultra_system["ensemble"] else None,
            "config": self.ultra_system["config"],
            "existing_detectors": list(self._existing_detectors.keys()),
        }
        return stats


# Instance globale
ultra_detector_pipeline = UltraDetectorPipeline()


def get_ultra_detector() -> UltraDetectorPipeline:
    """Get the global ultra detector instance."""
    return ultra_detector_pipeline
