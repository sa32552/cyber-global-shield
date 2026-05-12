"""
Cyber Global Shield — Kolmogorov-Arnold Networks (KAN) for Anomaly Detection
==========================================================================
KAN remplace les MLP (Multi-Layer Perceptrons) par des fonctions splines apprises,
offrant une précision supérieure avec moins de paramètres et une interprétabilité
intrinsèque via la visualisation des fonctions de base.

Théorie : Kolmogorov-Arnold representation theorem
  f(x₁,...,xₙ) = Σ_q Φ_q( Σ_p ψ_{p,q}(x_p) )
  
  Au lieu de poids linéaires + activation fixe (MLP),
  KAN apprend des fonctions splines sur les arêtes (ψ et Φ).

Architecture :
  - KANLayer : Couche KAN avec B-Splines apprises
  - KANNetwork : Réseau KAN multicouche
  - KANEnsemble : Ensemble de KANs avec Bayesian Model Averaging
  - KANAutoencoder : Autoencodeur KAN pour détection d'anomalies
  - KANAnomalyDetector : Détecteur complet intégré au pipeline
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone
import structlog
import math

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class KANResult:
    """Résultat de détection KAN unifié."""
    anomaly_score: float
    is_anomaly: bool
    threshold_used: float
    confidence: float
    reconstruction_error: float = 0.0
    spline_activations: Optional[Dict[str, np.ndarray]] = None
    feature_importance: Optional[Dict[str, float]] = None
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: KAN LAYER — B-Spline Basis Functions
# ═══════════════════════════════════════════════════════════════════════════

class BSplineBasis(nn.Module):
    """
    B-Spline basis functions for KAN layers.
    
    Implements recursive Cox-de Boor formula for B-Spline evaluation.
    Supports arbitrary degree, grid size, and learnable coefficients.
    
    Args:
        in_features: Number of input features
        out_features: Number of output features
        degree: Polynomial degree of B-Splines (default: 3 for cubic)
        grid_size: Number of intervals in the spline grid (default: 8)
        grid_range: Range of the grid [min, max] (default: [-1, 1])
    """
    
    def __init__(
        self,
        in_features: int,
        out_features: int,
        degree: int = 3,
        grid_size: int = 8,
        grid_range: List[float] = None,
    ):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.degree = degree
        self.grid_size = grid_size
        self.grid_range = grid_range or [-1.0, 1.0]
        
        # Number of basis functions per input feature
        self.n_basis = grid_size + degree
        
        # Learnable spline coefficients: [out_features, in_features, n_basis]
        self.spline_coeffs = nn.Parameter(
            torch.randn(out_features, in_features, self.n_basis) * 0.1
        )
        
        # Learnable residual (linear) weights: [out_features, in_features]
        self.residual_weight = nn.Parameter(
            torch.randn(out_features, in_features) * 0.1
        )
        
        # Learnable residual bias: [out_features]
        self.residual_bias = nn.Parameter(torch.zeros(out_features))
        
        # Grid points: [n_basis + 1]
        self.register_buffer(
            "grid",
            torch.linspace(grid_range[0], grid_range[1], self.n_basis + 1)
        )
        
        # Scaling factor for spline output
        self.scale_base = nn.Parameter(torch.ones(out_features, in_features) * 0.1)
        
        self._init_weights()
    
    def _init_weights(self):
        """Initialize weights with Xavier uniform."""
        nn.init.xavier_uniform_(self.spline_coeffs, gain=0.1)
        nn.init.xavier_uniform_(self.residual_weight, gain=0.1)
        nn.init.xavier_uniform_(self.scale_base, gain=0.1)
    
    def _bspline_basis(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute B-Spline basis functions using Cox-de Boor recursion.
        
        Args:
            x: Input tensor [batch_size, in_features]
        
        Returns:
            Basis functions [batch_size, in_features, n_basis]
        """
        batch_size = x.shape[0]
        x = x.unsqueeze(-1)  # [batch, in_features, 1]
        
        # Get grid points
        grid = self.grid  # [n_basis + 1]
        n_basis = self.n_basis
        
        # Initialize basis of degree 0
        # basis[i] = 1 if grid[i] <= x < grid[i+1]
        left = grid[:-1].unsqueeze(0).unsqueeze(0)  # [1, 1, n_basis]
        right = grid[1:].unsqueeze(0).unsqueeze(0)  # [1, 1, n_basis]
        
        basis = ((x >= left) & (x < right)).float()  # [batch, in_features, n_basis]
        
        # Cox-de Boor recursion for higher degrees
        for k in range(1, self.degree + 1):
            # Left and right terms
            left_num = x - grid[:n_basis + 1 - k].unsqueeze(0).unsqueeze(0)
            left_den = grid[k:n_basis + 1].unsqueeze(0).unsqueeze(0) - grid[:n_basis + 1 - k].unsqueeze(0).unsqueeze(0)
            left_term = torch.where(left_den > 1e-8, left_num / left_den, torch.zeros_like(left_num))
            
            right_num = grid[k + 1:n_basis + 2].unsqueeze(0).unsqueeze(0) - x
            right_den = grid[k + 1:n_basis + 2].unsqueeze(0).unsqueeze(0) - grid[1:n_basis + 1 - k].unsqueeze(0).unsqueeze(0)
            right_term = torch.where(right_den > 1e-8, right_num / right_den, torch.zeros_like(right_num))
            
            # Combine
            basis = left_term * basis[:, :, :-1] + right_term * basis[:, :, 1:]
        
        return basis  # [batch, in_features, n_basis]
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through KAN layer.
        
        Args:
            x: Input tensor [batch_size, in_features]
        
        Returns:
            Output tensor [batch_size, out_features]
        """
        batch_size = x.shape[0]
        
        # Clamp input to grid range
        x_clamped = torch.clamp(x, self.grid_range[0], self.grid_range[1])
        
        # Compute B-Spline basis
        basis = self._bspline_basis(x_clamped)  # [batch, in_features, n_basis]
        
        # Spline output: sum over basis functions weighted by coefficients
        # spline_coeffs: [out, in, n_basis]
        # basis: [batch, in, n_basis]
        spline_out = torch.einsum('oik,bik->bo', self.spline_coeffs, basis)
        
        # Residual (linear) output
        residual_out = F.linear(x, self.residual_weight, self.residual_bias)
        
        # Combine with learnable scaling
        # scale_base: [out, in] -> apply per-feature scaling
        scale_factor = torch.mean(self.scale_base, dim=1, keepdim=True)  # [out, 1]
        
        output = spline_out * scale_factor.squeeze(-1) + residual_out
        
        return output
    
    def get_spline_functions(self, x_range: Optional[List[float]] = None) -> Dict[str, Any]:
        """
        Get spline functions for visualization/interpretability.
        
        Returns:
            Dictionary with grid points and spline values per input-output pair
        """
        x_range = x_range or self.grid_range
        x_test = torch.linspace(x_range[0], x_range[1], 100).unsqueeze(-1)
        
        with torch.no_grad():
            basis = self._bspline_basis(x_test)
            # spline contribution per input-output pair
            spline_vals = torch.einsum('oik,bik->boi', self.spline_coeffs, basis)
        
        return {
            "grid": self.grid.cpu().numpy(),
            "x_values": x_test.squeeze(-1).cpu().numpy(),
            "spline_values": spline_vals.cpu().numpy(),
            "residual_weights": self.residual_weight.cpu().numpy(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: KAN NETWORK — Deep KAN Architecture
# ═══════════════════════════════════════════════════════════════════════════

class KANNetwork(nn.Module):
    """
    Deep Kolmogorov-Arnold Network.
    
    Stack of KAN layers with optional normalization and dropout.
    Suitable for classification and regression tasks.
    
    Args:
        layer_sizes: List of layer sizes [input_dim, hidden1, ..., output_dim]
        degree: B-Spline degree for all layers
        grid_size: Grid size for all layers
        dropout: Dropout rate between layers (default: 0.1)
        use_batch_norm: Whether to use batch normalization (default: True)
    """
    
    def __init__(
        self,
        layer_sizes: List[int],
        degree: int = 3,
        grid_size: int = 8,
        dropout: float = 0.1,
        use_batch_norm: bool = True,
    ):
        super().__init__()
        self.layer_sizes = layer_sizes
        self.num_layers = len(layer_sizes) - 1
        
        self.layers = nn.ModuleList()
        self.norms = nn.ModuleList()
        self.dropouts = nn.ModuleList()
        
        for i in range(self.num_layers):
            self.layers.append(
                BSplineBasis(
                    in_features=layer_sizes[i],
                    out_features=layer_sizes[i + 1],
                    degree=degree,
                    grid_size=grid_size,
                )
            )
            if use_batch_norm and i < self.num_layers - 1:
                self.norms.append(nn.BatchNorm1d(layer_sizes[i + 1]))
            else:
                self.norms.append(nn.Identity())
            
            if dropout > 0 and i < self.num_layers - 1:
                self.dropouts.append(nn.Dropout(dropout))
            else:
                self.dropouts.append(nn.Identity())
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass through all KAN layers."""
        for layer, norm, drop in zip(self.layers, self.norms, self.dropouts):
            x = layer(x)
            x = norm(x)
            if isinstance(norm, nn.BatchNorm1d) or not isinstance(norm, nn.Identity):
                pass  # activation already applied
            x = F.silu(x)  # SiLU activation between layers
            x = drop(x)
        return x
    
    def get_activations(self, x: torch.Tensor) -> Dict[str, np.ndarray]:
        """Get intermediate activations for interpretability."""
        activations = {}
        for i, (layer, norm, drop) in enumerate(zip(self.layers, self.norms, self.dropouts)):
            x = layer(x)
            activations[f"layer_{i}_pre"] = x.detach().cpu().numpy()
            x = norm(x)
            x = F.silu(x)
            activations[f"layer_{i}_post"] = x.detach().cpu().numpy()
            x = drop(x)
        activations["output"] = x.detach().cpu().numpy()
        return activations


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: KAN AUTOENCODER — Anomaly Detection via Reconstruction
# ═══════════════════════════════════════════════════════════════════════════

class KANAutoencoder(nn.Module):
    """
    KAN-based Autoencoder for anomaly detection.
    
    Uses KAN layers for both encoder and decoder, providing:
    - Better reconstruction than MLP autoencoders
    - Interpretable latent space via spline functions
    - Fewer parameters for same capacity
    
    Args:
        input_dim: Input feature dimension
        latent_dim: Latent space dimension (default: 32)
        hidden_dims: List of hidden layer dimensions (default: [128, 64])
        degree: B-Spline degree
        grid_size: Grid size for splines
    """
    
    def __init__(
        self,
        input_dim: int,
        latent_dim: int = 32,
        hidden_dims: List[int] = None,
        degree: int = 3,
        grid_size: int = 8,
    ):
        super().__init__()
        hidden_dims = hidden_dims or [128, 64]
        
        # Encoder: input_dim -> hidden_dims -> latent_dim
        encoder_sizes = [input_dim] + hidden_dims + [latent_dim]
        self.encoder = KANNetwork(
            layer_sizes=encoder_sizes,
            degree=degree,
            grid_size=grid_size,
            dropout=0.1,
        )
        
        # Decoder: latent_dim -> hidden_dims_rev -> input_dim
        decoder_sizes = [latent_dim] + list(reversed(hidden_dims)) + [input_dim]
        self.decoder = KANNetwork(
            layer_sizes=decoder_sizes,
            degree=degree,
            grid_size=grid_size,
            dropout=0.1,
        )
        
        self.input_dim = input_dim
        self.latent_dim = latent_dim
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through autoencoder.
        
        Returns:
            (reconstruction, latent_code)
        """
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction, latent
    
    def loss(self, x: torch.Tensor, reduction: str = "mean") -> torch.Tensor:
        """Compute reconstruction loss."""
        recon, latent = self.forward(x)
        recon_loss = F.mse_loss(recon, x, reduction=reduction)
        
        # L2 regularization on latent space
        latent_reg = torch.mean(latent ** 2) * 0.001
        
        return recon_loss + latent_reg
    
    def get_anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Compute per-sample anomaly score (reconstruction error)."""
        recon, _ = self.forward(x)
        return torch.mean((recon - x) ** 2, dim=-1)


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: KAN ENSEMBLE — Bayesian Model Averaging over KANs
# ═══════════════════════════════════════════════════════════════════════════

class KANEnsemble(nn.Module):
    """
    Ensemble of KAN networks with Bayesian Model Averaging.
    
    Trains multiple KANs with different initializations and combines
    their predictions using learned weights.
    
    Args:
        n_models: Number of KAN models in ensemble
        layer_sizes: Layer sizes for each KAN
        degree: B-Spline degree
        grid_size: Grid size
        dropout: Dropout rate
    """
    
    def __init__(
        self,
        n_models: int = 5,
        layer_sizes: List[int] = None,
        degree: int = 3,
        grid_size: int = 8,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.n_models = n_models
        self.layer_sizes = layer_sizes or [128, 64, 32, 1]
        
        self.models = nn.ModuleList([
            KANNetwork(
                layer_sizes=self.layer_sizes,
                degree=degree,
                grid_size=grid_size,
                dropout=dropout,
            )
            for _ in range(n_models)
        ])
        
        # Learnable ensemble weights
        self.ensemble_weights = nn.Parameter(torch.ones(n_models) / n_models)
        
        # Temperature for softmax weighting
        self.temperature = nn.Parameter(torch.tensor(1.0))
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass through ensemble.
        
        Returns:
            (weighted_prediction, individual_predictions, weights)
        """
        predictions = []
        for model in self.models:
            pred = model(x)
            predictions.append(pred)
        
        predictions = torch.stack(predictions, dim=-1)  # [batch, 1, n_models]
        weights = F.softmax(self.ensemble_weights / self.temperature, dim=-1)  # [n_models]
        
        weighted_pred = torch.sum(predictions * weights.unsqueeze(0).unsqueeze(0), dim=-1)
        
        return weighted_pred, predictions.squeeze(1), weights
    
    def get_uncertainty(self, x: torch.Tensor) -> torch.Tensor:
        """Get prediction uncertainty (variance across models)."""
        _, predictions, _ = self.forward(x)
        return torch.var(predictions, dim=-1)


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: KAN ANOMALY DETECTOR — Full Integration
# ═══════════════════════════════════════════════════════════════════════════

class KANAnomalyDetector:
    """
    Complete anomaly detector using KAN architecture.
    
    Integrates KANAutoencoder for reconstruction-based detection
    and KANEnsemble for uncertainty-aware classification.
    
    Usage:
        detector = KANAnomalyDetector(input_dim=128)
        detector.fit(train_data)
        result = detector.predict(sample)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        latent_dim: int = 32,
        hidden_dims: List[int] = None,
        degree: int = 3,
        grid_size: int = 8,
        n_ensemble: int = 5,
        threshold_percentile: float = 95.0,
        device: str = "cpu",
    ):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dims = hidden_dims or [128, 64]
        self.degree = degree
        self.grid_size = grid_size
        self.n_ensemble = n_ensemble
        self.threshold_percentile = threshold_percentile
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        
        # Autoencoder for reconstruction-based detection
        self.autoencoder = KANAutoencoder(
            input_dim=input_dim,
            latent_dim=latent_dim,
            hidden_dims=self.hidden_dims,
            degree=degree,
            grid_size=grid_size,
        ).to(self.device)
        
        # Ensemble for classification
        ensemble_sizes = [input_dim] + self.hidden_dims + [1]
        self.ensemble = KANEnsemble(
            n_models=n_ensemble,
            layer_sizes=ensemble_sizes,
            degree=degree,
            grid_size=grid_size,
        ).to(self.device)
        
        self.threshold: float = 0.0
        self.trained = False
        self.train_scores: List[float] = []
        self.metrics_history: Dict[str, List[float]] = {
            "train_loss": [],
            "val_loss": [],
            "ensemble_loss": [],
        }
    
    def fit(
        self,
        X: np.ndarray,
        y: Optional[np.ndarray] = None,
        epochs: int = 100,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        val_split: float = 0.1,
        verbose: bool = True,
    ):
        """
        Train the KAN detector on normal data.
        
        Args:
            X: Training data [n_samples, input_dim]
            y: Optional labels (for ensemble training if available)
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            val_split: Validation split ratio
            verbose: Print progress
        """
        n_samples = X.shape[0]
        n_val = int(n_samples * val_split)
        n_train = n_samples - n_val
        
        # Split data
        indices = np.random.permutation(n_samples)
        train_idx = indices[:n_train]
        val_idx = indices[n_train:]
        
        X_train = torch.FloatTensor(X[train_idx]).to(self.device)
        X_val = torch.FloatTensor(X[val_idx]).to(self.device)
        
        # Optimizers
        ae_optimizer = torch.optim.AdamW(
            self.autoencoder.parameters(), lr=learning_rate, weight_decay=1e-5
        )
        ensemble_optimizer = torch.optim.AdamW(
            self.ensemble.parameters(), lr=learning_rate, weight_decay=1e-5
        )
        
        # Schedulers
        ae_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            ae_optimizer, T_max=epochs
        )
        ensemble_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            ensemble_optimizer, T_max=epochs
        )
        
        best_val_loss = float("inf")
        patience = 10
        patience_counter = 0
        
        for epoch in range(epochs):
            # --- Train Autoencoder ---
            self.autoencoder.train()
            ae_losses = []
            
            for i in range(0, len(X_train), batch_size):
                batch = X_train[i:i + batch_size]
                
                ae_optimizer.zero_grad()
                loss = self.autoencoder.loss(batch)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.autoencoder.parameters(), 1.0)
                ae_optimizer.step()
                
                ae_losses.append(loss.item())
            
            # --- Train Ensemble (if labels available) ---
            ensemble_losses = []
            if y is not None:
                y_train = torch.FloatTensor(y[train_idx]).to(self.device)
                self.ensemble.train()
                
                for i in range(0, len(X_train), batch_size):
                    batch_x = X_train[i:i + batch_size]
                    batch_y = y_train[i:i + batch_size]
                    
                    ensemble_optimizer.zero_grad()
                    pred, _, _ = self.ensemble(batch_x)
                    loss = F.binary_cross_entropy_with_logits(pred.squeeze(), batch_y)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.ensemble.parameters(), 1.0)
                    ensemble_optimizer.step()
                    
                    ensemble_losses.append(loss.item())
            
            # --- Validation ---
            self.autoencoder.eval()
            with torch.no_grad():
                val_loss = self.autoencoder.loss(X_val).item()
            
            # Learning rate scheduling
            ae_scheduler.step()
            ensemble_scheduler.step()
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    if verbose:
                        logger.info(f"Early stopping at epoch {epoch}")
                    break
            
            # Logging
            self.metrics_history["train_loss"].append(np.mean(ae_losses))
            self.metrics_history["val_loss"].append(val_loss)
            if ensemble_losses:
                self.metrics_history["ensemble_loss"].append(np.mean(ensemble_losses))
            
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    "KAN training progress",
                    epoch=epoch + 1,
                    train_loss=np.mean(ae_losses),
                    val_loss=val_loss,
                )
        
        # Compute threshold from training data
        self.autoencoder.eval()
        with torch.no_grad():
            scores = self.autoencoder.get_anomaly_score(X_train)
            self.train_scores = scores.cpu().numpy().tolist()
            self.threshold = np.percentile(
                self.train_scores, self.threshold_percentile
            )
        
        self.trained = True
        logger.info(
            "KAN training complete",
            threshold=self.threshold,
            best_val_loss=best_val_loss,
        )
    
    def predict(self, X: np.ndarray) -> List[KANResult]:
        """
        Predict anomalies on new data.
        
        Args:
            X: Input data [n_samples, input_dim]
        
        Returns:
            List of KANResult objects
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        self.autoencoder.eval()
        self.ensemble.eval()
        
        results = []
        start_time = datetime.now(timezone.utc)
        
        with torch.no_grad():
            # Reconstruction scores
            recon_scores = self.autoencoder.get_anomaly_score(X_tensor)
            
            # Ensemble predictions
            ensemble_pred, individual_preds, weights = self.ensemble(X_tensor)
            ensemble_probs = torch.sigmoid(ensemble_pred).squeeze(-1)
            uncertainty = torch.var(individual_preds, dim=-1)
            
            # Combine scores
            normalized_recon = (recon_scores - recon_scores.mean()) / (recon_scores.std() + 1e-8)
            combined_scores = 0.5 * normalized_recon + 0.5 * ensemble_probs
            combined_scores = torch.sigmoid(combined_scores)
        
        inference_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
        for i in range(len(X)):
            is_anomaly = combined_scores[i].item() > self.threshold
            
            # Feature importance via spline activations
            feature_importance = None
            if hasattr(self.autoencoder.encoder.layers[0], 'get_spline_functions'):
                spline_info = self.autoencoder.encoder.layers[0].get_spline_functions()
                feature_importance = {
                    "spline_grid": spline_info["grid"].tolist(),
                    "residual_weights": spline_info["residual_weights"].tolist(),
                }
            
            result = KANResult(
                anomaly_score=combined_scores[i].item(),
                is_anomaly=is_anomaly,
                threshold_used=self.threshold,
                confidence=1.0 - uncertainty[i].item(),
                reconstruction_error=recon_scores[i].item(),
                spline_activations=None,
                feature_importance=feature_importance,
                explanation=self._generate_explanation(
                    combined_scores[i].item(),
                    recon_scores[i].item(),
                    uncertainty[i].item(),
                ),
                inference_time_ms=inference_time / len(X),
            )
            results.append(result)
        
        return results
    
    def _generate_explanation(
        self, score: float, recon_error: float, uncertainty: float
    ) -> str:
        """Generate human-readable explanation."""
        parts = []
        if score > self.threshold:
            parts.append(f"Anomaly detected (score={score:.3f}, threshold={self.threshold:.3f})")
        else:
            parts.append(f"Normal behavior (score={score:.3f})")
        
        parts.append(f"Reconstruction error: {recon_error:.4f}")
        parts.append(f"Model confidence: {(1 - uncertainty) * 100:.1f}%")
        
        if recon_error > np.mean(self.train_scores) + 2 * np.std(self.train_scores):
            parts.append("⚠ High reconstruction error suggests novel pattern")
        
        return " | ".join(parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "architecture": "KAN",
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "hidden_dims": self.hidden_dims,
            "degree": self.degree,
            "grid_size": self.grid_size,
            "n_ensemble": self.n_ensemble,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "trained": self.trained,
            "n_train_samples": len(self.train_scores),
            "mean_train_score": float(np.mean(self.train_scores)) if self.train_scores else 0.0,
            "std_train_score": float(np.std(self.train_scores)) if self.train_scores else 0.0,
            "metrics_history": {
                k: v[-10:] if len(v) > 10 else v
                for k, v in self.metrics_history.items()
            },
            "n_parameters": sum(
                p.numel() for p in self.autoencoder.parameters()
            ) + sum(
                p.numel() for p in self.ensemble.parameters()
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_kan_detector(
    input_dim: int = 128,
    latent_dim: int = 32,
    degree: int = 3,
    grid_size: int = 8,
    device: str = "cpu",
) -> KANAnomalyDetector:
    """
    Create a default KAN anomaly detector.
    
    Args:
        input_dim: Input feature dimension
        latent_dim: Latent space dimension
        degree: B-Spline polynomial degree
        grid_size: Number of grid intervals
        device: Device to use
    
    Returns:
        Configured KANAnomalyDetector
    """
    return KANAnomalyDetector(
        input_dim=input_dim,
        latent_dim=latent_dim,
        hidden_dims=[128, 64],
        degree=degree,
        grid_size=grid_size,
        n_ensemble=5,
        threshold_percentile=95.0,
        device=device,
    )


def create_kan_detector_minimal() -> Dict[str, Any]:
    """Create a minimal KAN detector config for quick testing."""
    return {
        "type": "kan",
        "input_dim": 128,
        "latent_dim": 16,
        "hidden_dims": [64],
        "degree": 2,
        "grid_size": 5,
        "n_ensemble": 3,
        "threshold_percentile": 90.0,
    }


def create_kan_detector_full() -> Dict[str, Any]:
    """Create a full KAN detector config for production."""
    return {
        "type": "kan",
        "input_dim": 256,
        "latent_dim": 64,
        "hidden_dims": [256, 128, 64],
        "degree": 3,
        "grid_size": 12,
        "n_ensemble": 10,
        "threshold_percentile": 99.0,
    }
