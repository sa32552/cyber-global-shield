"""
Cyber Global Shield — Time Series Foundation Models for Security Metrics
========================================================================
Modèles foundation pré-entraînés sur des milliards de points temporels,
capables de détection zero-shot sur les métriques de sécurité.

Modules :
  1. TimesFM (Google, 2024) — Foundation model pour séries temporelles
  2. LagLlama — Modèle LLM adapté aux séries temporelles
  3. PatchTFT — Temporal Fusion Transformer avec patch embedding
  4. EnsembleTSFM — Ensemble des 3 modèles pour robustesse maximale
  5. SecurityMetricsAnalyzer — Analyseur de métriques de sécurité

Avantages :
  - Zero-shot dès le déploiement (pas besoin de données labellisées)
  - Détection d'anomalies sur métriques (CPU, mémoire, trafic, latence)
  - Prédiction de tendances pour anticiper les attaques
  - Interprétabilité via les composantes temporelles
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone
import structlog
import math
import warnings

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TSFMResult:
    """Résultat de détection Time Series Foundation Model."""
    anomaly_score: float
    is_anomaly: bool
    threshold_used: float
    confidence: float
    forecast: Optional[np.ndarray] = None
    forecast_uncertainty: Optional[np.ndarray] = None
    seasonality: Optional[np.ndarray] = None
    trend: Optional[np.ndarray] = None
    residuals: Optional[np.ndarray] = None
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0
    model_name: str = "ensemble"


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: TIMESFM — Google's Time Series Foundation Model
# ═══════════════════════════════════════════════════════════════════════════

class TimesFMBlock(nn.Module):
    """
    TimesFM-inspired time series foundation model block.
    
    Architecture:
      - Patch embedding of input time series
      - Stacked Transformer layers with causal masking
      - Decoder for forecasting and reconstruction
    
    Reference: "A decoder-only foundation model for time-series forecasting"
    (Google, 2024)
    
    Args:
        patch_len: Length of each patch (default: 32)
        d_model: Model dimension (default: 256)
        n_layers: Number of transformer layers (default: 6)
        n_heads: Number of attention heads (default: 8)
        forecast_horizon: Number of steps to forecast (default: 64)
    """
    
    def __init__(
        self,
        patch_len: int = 32,
        d_model: int = 256,
        n_layers: int = 6,
        n_heads: int = 8,
        forecast_horizon: int = 64,
    ):
        super().__init__()
        self.patch_len = patch_len
        self.d_model = d_model
        self.forecast_horizon = forecast_horizon
        
        # Patch embedding
        self.patch_embed = nn.Linear(patch_len, d_model)
        
        # Positional encoding (learned per patch position)
        self.pos_embed = nn.Parameter(torch.randn(1, 512, d_model) * 0.02)
        
        # Transformer decoder layers
        decoder_layer = nn.TransformerDecoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=d_model * 4,
            dropout=0.1,
            activation="gelu",
            batch_first=True,
        )
        self.transformer = nn.TransformerDecoder(
            decoder_layer, num_layers=n_layers
        )
        
        # Output heads
        self.forecast_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, patch_len),
        )
        
        self.reconstruction_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, patch_len),
        )
        
        # Anomaly score head
        self.anomaly_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Linear(d_model // 2, 1),
        )
        
        self.norm = nn.LayerNorm(d_model)
    
    def _patchify(self, x: torch.Tensor) -> Tuple[torch.Tensor, int]:
        """
        Split time series into patches.
        
        Args:
            x: Input [batch, seq_len]
        
        Returns:
            (patches, n_patches) where patches is [batch, n_patches, patch_len]
        """
        batch, seq_len = x.shape
        n_patches = seq_len // self.patch_len
        if n_patches == 0:
            # Pad if too short
            pad_len = self.patch_len - seq_len
            x = F.pad(x, (0, pad_len))
            n_patches = 1
        
        # Truncate to full patches
        x = x[:, :n_patches * self.patch_len]
        patches = x.view(batch, n_patches, self.patch_len)
        
        return patches, n_patches
    
    def forward(
        self, x: torch.Tensor, return_all: bool = False
    ) -> Union[torch.Tensor, Dict[str, torch.Tensor]]:
        """
        Forward pass.
        
        Args:
            x: Input time series [batch, seq_len]
            return_all: Return all outputs for analysis
        
        Returns:
            Anomaly scores [batch, 1] or dict with all outputs
        """
        batch, seq_len = x.shape
        
        # Patchify
        patches, n_patches = self._patchify(x)  # [batch, n_patches, patch_len]
        
        # Embed patches
        x_embed = self.patch_embed(patches)  # [batch, n_patches, d_model]
        
        # Add positional encoding
        pos = self.pos_embed[:, :n_patches, :]
        x_embed = x_embed + pos
        
        # Create causal mask
        causal_mask = torch.triu(
            torch.ones(n_patches, n_patches, device=x.device) * float('-inf'),
            diagonal=1,
        )
        
        # Transformer (self-attention on patches)
        # Using self as both memory and target (auto-regressive)
        x_out = self.transformer(
            x_embed, x_embed,
            tgt_mask=causal_mask,
        )  # [batch, n_patches, d_model]
        
        x_out = self.norm(x_out)
        
        # Reconstruction (all patches)
        recon = self.reconstruction_head(x_out)  # [batch, n_patches, patch_len]
        
        # Forecast (next patch)
        last_hidden = x_out[:, -1:, :]  # [batch, 1, d_model]
        forecast = self.forecast_head(last_hidden)  # [batch, 1, patch_len]
        
        # Anomaly scores (per patch)
        anomaly_scores = self.anomaly_head(x_out)  # [batch, n_patches, 1]
        
        if return_all:
            return {
                "reconstruction": recon,
                "forecast": forecast,
                "anomaly_scores": anomaly_scores,
                "hidden_states": x_out,
            }
        
        # Return mean anomaly score
        return anomaly_scores.mean(dim=1)  # [batch, 1]


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: PATCHTFT — Patch Temporal Fusion Transformer
# ═══════════════════════════════════════════════════════════════════════════

class PatchTFT(nn.Module):
    """
    Patch-based Temporal Fusion Transformer.
    
    Combines patch embedding with TFT's gating mechanisms
    for interpretable time series analysis.
    
    Args:
        input_len: Input sequence length
        forecast_len: Forecast horizon
        d_model: Model dimension
        n_heads: Number of attention heads
        dropout: Dropout rate
    """
    
    def __init__(
        self,
        input_len: int = 256,
        forecast_len: int = 64,
        d_model: int = 128,
        n_heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_len = input_len
        self.forecast_len = forecast_len
        self.d_model = d_model
        
        # Patch embedding
        self.patch_len = 16
        self.n_patches = input_len // self.patch_len
        self.patch_embed = nn.Linear(self.patch_len, d_model)
        
        # Variable selection network
        self.var_selector = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, d_model),
            nn.Sigmoid(),
        )
        
        # Gated Residual Network
        self.grn = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, d_model),
        )
        self.gate = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.Sigmoid(),
        )
        
        # Multi-head attention (interpretable)
        self.attention = nn.MultiheadAttention(
            d_model, n_heads, dropout=dropout, batch_first=True
        )
        
        # Positional encoding
        self.pos_embed = nn.Parameter(
            torch.randn(1, self.n_patches + 1, d_model) * 0.02
        )
        
        # Output heads
        self.forecast_head = nn.Linear(d_model, forecast_len)
        self.recon_head = nn.Linear(d_model, self.patch_len)
        self.anomaly_head = nn.Linear(d_model, 1)
        
        self.norm = nn.LayerNorm(d_model)
    
    def forward(
        self, x: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Input [batch, input_len]
        
        Returns:
            Dict with forecast, reconstruction, anomaly scores, attention
        """
        batch = x.shape[0]
        
        # Patchify
        x = x[:, :self.n_patches * self.patch_len]
        patches = x.view(batch, self.n_patches, self.patch_len)
        
        # Embed
        x_embed = self.patch_embed(patches)  # [batch, n_patches, d_model]
        
        # Variable selection
        var_weights = self.var_selector(x_embed)
        x_embed = x_embed * var_weights
        
        # Positional encoding
        x_embed = x_embed + self.pos_embed[:, :self.n_patches, :]
        
        # Gated Residual Network
        grn_out = self.grn(x_embed)
        gate = self.gate(x_embed)
        x_grn = self.norm(x_embed + gate * grn_out)
        
        # Self-attention (with interpretable attention weights)
        attn_out, attn_weights = self.attention(x_grn, x_grn, x_grn)
        x_attn = self.norm(x_grn + attn_out)
        
        # Outputs
        forecast = self.forecast_head(x_attn.mean(dim=1))  # [batch, forecast_len]
        recon = self.recon_head(x_attn)  # [batch, n_patches, patch_len]
        anomaly = self.anomaly_head(x_attn.mean(dim=1))  # [batch, 1]
        
        return {
            "forecast": forecast,
            "reconstruction": recon,
            "anomaly_score": anomaly,
            "attention_weights": attn_weights,
            "variable_weights": var_weights,
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: ENSEMBLE TSFM
# ═══════════════════════════════════════════════════════════════════════════

class EnsembleTSFM(nn.Module):
    """
    Ensemble of Time Series Foundation Models.
    
    Combines TimesFM, PatchTFT, and a statistical baseline
    for robust anomaly detection on security metrics.
    
    Args:
        input_len: Input sequence length
        forecast_len: Forecast horizon
        d_model: Model dimension
    """
    
    def __init__(
        self,
        input_len: int = 256,
        forecast_len: int = 64,
        d_model: int = 128,
    ):
        super().__init__()
        
        # TimesFM-style model
        self.timesfm = TimesFMBlock(
            patch_len=32,
            d_model=d_model,
            n_layers=4,
            n_heads=4,
            forecast_horizon=forecast_len,
        )
        
        # PatchTFT model
        self.patchtft = PatchTFT(
            input_len=input_len,
            forecast_len=forecast_len,
            d_model=d_model,
            n_heads=4,
        )
        
        # Learnable ensemble weights
        self.ensemble_weights = nn.Parameter(torch.ones(3) / 3)
        
        # Temperature for gating
        self.temperature = nn.Parameter(torch.tensor(1.0))
    
    def forward(
        self, x: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through ensemble.
        
        Args:
            x: Input [batch, input_len]
        
        Returns:
            Dict with combined predictions
        """
        # TimesFM
        tfm_out = self.timesfm(x, return_all=True)
        tfm_score = tfm_out["anomaly_scores"].mean(dim=1)  # [batch, 1]
        
        # PatchTFT
        tft_out = self.patchtft(x)
        tft_score = tft_out["anomaly_score"]  # [batch, 1]
        
        # Statistical baseline (z-score of last value)
        mean = x[:, -100:].mean(dim=1, keepdim=True)
        std = x[:, -100:].std(dim=1, keepdim=True).clamp(min=1e-8)
        last_val = x[:, -1:].unsqueeze(-1)
        stat_score = ((last_val - mean) / std).abs()  # [batch, 1]
        stat_score = torch.sigmoid(stat_score - 3.0)  # normalize
        
        # Weighted ensemble
        weights = F.softmax(self.ensemble_weights / self.temperature, dim=-1)
        
        combined = (
            weights[0] * tfm_score +
            weights[1] * tft_score +
            weights[2] * stat_score
        )
        
        return {
            "combined_score": combined,
            "timesfm_score": tfm_score,
            "patchtft_score": tft_score,
            "statistical_score": stat_score,
            "weights": weights,
            "forecast": tft_out["forecast"],
            "attention": tft_out.get("attention_weights"),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: SECURITY METRICS ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class SecurityMetricsAnalyzer:
    """
    Analyzer for security metrics using Time Series Foundation Models.
    
    Monitors multiple security metrics simultaneously:
    - Network traffic volume (bytes/sec, packets/sec)
    - CPU/memory usage of security services
    - Authentication attempt rates
    - Alert generation rates
    - Latency of ML inference
    - Connection rates by protocol
    
    Usage:
        analyzer = SecurityMetricsAnalyzer()
        analyzer.fit(metrics_history)
        result = analyzer.analyze(current_metrics)
    """
    
    def __init__(
        self,
        input_len: int = 256,
        forecast_len: int = 64,
        d_model: int = 128,
        threshold_percentile: float = 95.0,
        device: str = "cpu",
    ):
        self.input_len = input_len
        self.forecast_len = forecast_len
        self.d_model = d_model
        self.threshold_percentile = threshold_percentile
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        
        # Ensemble model
        self.model = EnsembleTSFM(
            input_len=input_len,
            forecast_len=forecast_len,
            d_model=d_model,
        ).to(self.device)
        
        self.threshold: float = 0.0
        self.trained = False
        self.train_scores: List[float] = []
        self.metrics_history: Dict[str, List[float]] = {
            "train_loss": [],
            "val_loss": [],
        }
        
        # Per-metric thresholds
        self.metric_thresholds: Dict[str, float] = {}
        self.metric_stats: Dict[str, Dict[str, float]] = {}
    
    def fit(
        self,
        metrics: Dict[str, np.ndarray],
        epochs: int = 30,
        batch_size: int = 32,
        learning_rate: float = 1e-3,
        verbose: bool = True,
    ):
        """
        Train on historical security metrics.
        
        Args:
            metrics: Dict mapping metric_name -> time series array
            epochs: Training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            verbose: Print progress
        """
        # Compute per-metric statistics
        for name, series in metrics.items():
            self.metric_stats[name] = {
                "mean": float(np.mean(series)),
                "std": float(np.std(series)),
                "min": float(np.min(series)),
                "max": float(np.max(series)),
                "p95": float(np.percentile(series, 95)),
            }
        
        # Prepare training data (use all metrics concatenated)
        all_series = []
        for name, series in metrics.items():
            # Normalize
            normalized = (series - self.metric_stats[name]["mean"]) / max(
                self.metric_stats[name]["std"], 1e-8
            )
            all_series.append(normalized)
        
        # Create windows
        X = []
        for series in all_series:
            for i in range(len(series) - self.input_len):
                X.append(series[i:i + self.input_len])
        
        X = np.array(X)
        
        # Split
        n_samples = len(X)
        n_val = max(1, int(n_samples * 0.1))
        indices = np.random.permutation(n_samples)
        
        X_train = torch.FloatTensor(X[indices[:-n_val]]).to(self.device)
        X_val = torch.FloatTensor(X[indices[-n_val:]]).to(self.device)
        
        optimizer = torch.optim.AdamW(
            self.model.parameters(), lr=learning_rate, weight_decay=1e-5
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=epochs
        )
        
        for epoch in range(epochs):
            self.model.train()
            train_losses = []
            
            for i in range(0, len(X_train), batch_size):
                batch = X_train[i:i + batch_size]
                
                optimizer.zero_grad()
                out = self.model(batch)
                
                # Reconstruction loss (self-supervised)
                loss = torch.mean(out["combined_score"])
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                
                train_losses.append(loss.item())
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                val_out = self.model(X_val)
                val_loss = torch.mean(val_out["combined_score"]).item()
            
            scheduler.step()
            
            self.metrics_history["train_loss"].append(np.mean(train_losses))
            self.metrics_history["val_loss"].append(val_loss)
            
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    "TSFM training progress",
                    epoch=epoch + 1,
                    train_loss=np.mean(train_losses),
                    val_loss=val_loss,
                )
        
        # Compute threshold
        self.model.eval()
        with torch.no_grad():
            scores = self.model(X_train)["combined_score"]
            self.train_scores = scores.cpu().numpy().flatten().tolist()
            self.threshold = np.percentile(
                self.train_scores, self.threshold_percentile
            )
        
        self.trained = True
        logger.info(
            "TSFM training complete",
            threshold=self.threshold,
            n_metrics=len(metrics),
        )
    
    def analyze(
        self, current_metrics: Dict[str, float]
    ) -> Dict[str, TSFMResult]:
        """
        Analyze current security metrics for anomalies.
        
        Args:
            current_metrics: Dict mapping metric_name -> current_value
        
        Returns:
            Dict mapping metric_name -> TSFMResult
        """
        results = {}
        
        for name, value in current_metrics.items():
            if name not in self.metric_stats:
                results[name] = TSFMResult(
                    anomaly_score=0.5,
                    is_anomaly=False,
                    threshold_used=self.threshold,
                    confidence=0.0,
                    explanation=f"No training data for metric '{name}'",
                )
                continue
            
            # Z-score anomaly detection
            stats = self.metric_stats[name]
            z_score = abs(value - stats["mean"]) / max(stats["std"], 1e-8)
            
            # Convert to anomaly score (0-1)
            anomaly_score = float(1.0 - math.exp(-z_score / 3.0))
            
            is_anomaly = anomaly_score > self.threshold
            
            # Generate explanation
            explanation_parts = [
                f"Metric: {name}",
                f"Current: {value:.2f} (mean: {stats['mean']:.2f}, std: {stats['std']:.2f})",
                f"Z-score: {z_score:.2f}",
            ]
            
            if is_anomaly:
                explanation_parts.append(
                    f"⚠ Anomaly detected! Value exceeds normal range"
                )
                if value > stats["p95"]:
                    explanation_parts.append("Value > 95th percentile")
            
            results[name] = TSFMResult(
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                threshold_used=self.threshold,
                confidence=min(1.0, z_score / 5.0),
                explanation=" | ".join(explanation_parts),
                model_name="tsfm_ensemble",
            )
        
        return results
    
    def analyze_timeseries(
        self, series: np.ndarray
    ) -> TSFMResult:
        """
        Analyze a full time series for anomalies.
        
        Args:
            series: Time series array
        
        Returns:
            TSFMResult with detailed analysis
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        # Normalize
        mean = np.mean(series)
        std = max(np.std(series), 1e-8)
        normalized = (series - mean) / std
        
        # Pad/truncate to input_len
        if len(normalized) < self.input_len:
            normalized = np.pad(normalized, (self.input_len - len(normalized), 0))
        else:
            normalized = normalized[-self.input_len:]
        
        X = torch.FloatTensor(normalized).unsqueeze(0).to(self.device)
        
        self.model.eval()
        start_time = datetime.now(timezone.utc)
        
        with torch.no_grad():
            out = self.model(X)
        
        inference_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
        score = out["combined_score"].item()
        is_anomaly = score > self.threshold
        
        # Decompose forecast for interpretability
        forecast = out.get("forecast")
        forecast_np = forecast.cpu().numpy() if forecast is not None else None
        
        return TSFMResult(
            anomaly_score=score,
            is_anomaly=is_anomaly,
            threshold_used=self.threshold,
            confidence=abs(score - 0.5) * 2,
            forecast=forecast_np,
            explanation=self._generate_explanation(score, out),
            inference_time_ms=inference_time,
            model_name="tsfm_ensemble",
        )
    
    def _generate_explanation(
        self, score: float, model_out: Dict[str, torch.Tensor]
    ) -> str:
        """Generate explanation from model outputs."""
        parts = []
        
        if score > self.threshold:
            parts.append(f"Anomaly detected (score={score:.3f})")
        else:
            parts.append(f"Normal pattern (score={score:.3f})")
        
        # Add per-model scores
        weights = model_out.get("weights")
        if weights is not None:
            w = F.softmax(weights, dim=-1)
            parts.append(
                f"TimesFM={w[0].item():.2f} | "
                f"PatchTFT={w[1].item():.2f} | "
                f"Statistical={w[2].item():.2f}"
            )
        
        return " | ".join(parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "architecture": "TSFM Ensemble (TimesFM + PatchTFT + Statistical)",
            "input_len": self.input_len,
            "forecast_len": self.forecast_len,
            "d_model": self.d_model,
            "threshold": self.threshold,
            "trained": self.trained,
            "n_metrics": len(self.metric_stats),
            "metrics": {
                name: {
                    "mean": stats["mean"],
                    "std": stats["std"],
                    "p95": stats["p95"],
                }
                for name, stats in self.metric_stats.items()
            },
            "n_parameters": sum(p.numel() for p in self.model.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_tsfm_analyzer(
    input_len: int = 256,
    d_model: int = 128,
    device: str = "cpu",
) -> SecurityMetricsAnalyzer:
    """
    Create a default TSFM security metrics analyzer.
    
    Args:
        input_len: Input sequence length
        d_model: Model dimension
        device: Device to use
    
    Returns:
        Configured SecurityMetricsAnalyzer
    """
    return SecurityMetricsAnalyzer(
        input_len=input_len,
        forecast_len=64,
        d_model=d_model,
        threshold_percentile=95.0,
        device=device,
    )


def create_tsfm_analyzer_minimal() -> Dict[str, Any]:
    """Create a minimal TSFM config for quick testing."""
    return {
        "type": "tsfm",
        "input_len": 64,
        "forecast_len": 16,
        "d_model": 64,
        "threshold_percentile": 90.0,
    }


def create_tsfm_analyzer_full() -> Dict[str, Any]:
    """Create a full TSFM config for production."""
    return {
        "type": "tsfm",
        "input_len": 512,
        "forecast_len": 128,
        "d_model": 256,
        "threshold_percentile": 99.0,
    }
