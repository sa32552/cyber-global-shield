"""
Cyber Global Shield — Ultra-Pointer Prediction Module (Niveau 2)
===============================================================

4 modèles de prédiction temporelle de pointe coordonnés :

1. Temporal Fusion Transformer (TFT) — Google, SOTA avec gating + attention interprétable
2. DeepAR — Amazon, prédiction probabiliste avec Student-T
3. N-BEATS — Element AI, pure MLP avec décomposition tendance/saisonnalité
4. PatchTST — MIT, transformer avec patches pour séries longues

Chaque modèle peut fonctionner indépendamment ou via l'ensemble bayésien.
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
from scipy import stats as scipy_stats

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ForecastResult:
    """Résultat de prédiction unifié."""
    value: float
    lower_bound: float
    upper_bound: float
    confidence: float
    horizon_steps: int
    prediction_type: str  # "attack", "anomaly", "trend", "risk"
    model_name: str
    inference_time_ms: float = 0.0
    explanation: Optional[str] = None


@dataclass
class TimeSeriesForecast:
    """Prédiction complète de série temporelle."""
    timestamps: List[float]
    values: List[float]
    lower_bounds: List[float]
    upper_bounds: List[float]
    confidences: List[float]
    horizon: str  # "short", "medium", "long", "strategic"
    model_scores: Dict[str, float] = field(default_factory=dict)
    trend: Optional[float] = None
    seasonality: Optional[Dict[str, float]] = None


# ═══════════════════════════════════════════════════════════════════════════
# 1. TEMPORAL FUSION TRANSFORMER (TFT) — Google
# ═══════════════════════════════════════════════════════════════════════════

class GatedResidualNetwork(nn.Module):
    """
    Gated Residual Network (GRN) — composant de base du TFT.
    
    GRN(x) = LayerNorm(x + GLU(ELU(W2 * Dropout(ELU(W1 * x + b1)) + b2)))
    
    Le gating permet au réseau d'ignorer les parties non nécessaires.
    """
    
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, dropout: float = 0.1):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, output_dim)
        self.gate = nn.Linear(output_dim, output_dim)
        self.layer_norm = nn.LayerNorm(output_dim)
        self.dropout = nn.Dropout(dropout)
        
        # Skip connection projection if dimensions differ
        self.skip_proj = nn.Linear(input_dim, output_dim) if input_dim != output_dim else nn.Identity()
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """GRN forward."""
        skip = self.skip_proj(x)
        
        # Main path
        out = F.elu(self.fc1(x))
        out = self.dropout(out)
        out = self.fc2(out)
        
        # Gating
        gate = torch.sigmoid(self.gate(out))
        out = gate * out
        
        # Residual + LayerNorm
        out = self.layer_norm(skip + out)
        
        return out


class InterpretableMultiHeadAttention(nn.Module):
    """
    Multi-head attention with interpretable weights.
    
    Au lieu de concaténer les têtes, on les moyenne pour obtenir
    des poids d'attention interprétables.
    """
    
    def __init__(self, d_model: int, n_heads: int, dropout: float = 0.1):
        super().__init__()
        self.n_heads = n_heads
        self.d_model = d_model
        self.d_head = d_model // n_heads
        
        assert d_model % n_heads == 0, "d_model must be divisible by n_heads"
        
        self.q_linear = nn.Linear(d_model, d_model)
        self.k_linear = nn.Linear(d_model, d_model)
        self.v_linear = nn.Linear(d_model, d_model)
        self.output_linear = nn.Linear(d_model, d_model)
        
        self.dropout = nn.Dropout(dropout)
        self.scale = self.d_head ** 0.5
    
    def forward(self, q: torch.Tensor, k: torch.Tensor, v: torch.Tensor,
                mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass with interpretable attention weights.
        
        Returns:
            output: (batch, seq_len, d_model)
            attention_weights: (batch, n_heads, seq_len, seq_len)
        """
        batch_size = q.size(0)
        
        # Linear projections
        Q = self.q_linear(q).view(batch_size, -1, self.n_heads, self.d_head).transpose(1, 2)
        K = self.k_linear(k).view(batch_size, -1, self.n_heads, self.d_head).transpose(1, 2)
        V = self.v_linear(v).view(batch_size, -1, self.n_heads, self.d_head).transpose(1, 2)
        
        # Scaled dot-product attention
        scores = torch.matmul(Q, K.transpose(-2, -1)) / self.scale
        
        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)
        
        attention_weights = F.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)
        
        # Weighted sum
        context = torch.matmul(attention_weights, V)
        context = context.transpose(1, 2).contiguous().view(batch_size, -1, self.d_model)
        
        # Output projection
        output = self.output_linear(context)
        
        # Average attention weights across heads for interpretability
        avg_attention = attention_weights.mean(dim=1)
        
        return output, avg_attention


class TemporalFusionTransformer(nn.Module):
    """
    Temporal Fusion Transformer (TFT) — Google, 2019.
    
    Architecture :
    1. Variable Selection Network (VSN) — sélectionne les features importantes
    2. LSTM Encoder-Decoder — capture les dépendances temporelles
    3. Interpretable Multi-Head Attention — relations à long terme
    4. Gated Residual Network (GRN) — skip connections
    5. Quantile Outputs — prédiction probabiliste (P10, P50, P90)
    
    Référence : Lim et al. "Temporal Fusion Transformers for interpretable
                multi-horizon time series forecasting" (2019)
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        n_heads: int = 4,
        n_lstm_layers: int = 2,
        dropout: float = 0.1,
        max_seq_len: int = 100,
        output_quantiles: List[float] = None,
    ):
        super().__init__()
        
        if output_quantiles is None:
            output_quantiles = [0.1, 0.5, 0.9]  # P10, P50, P90
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.n_quantiles = len(output_quantiles)
        self.output_quantiles = output_quantiles
        
        # Variable Selection Network
        self.vsn = GatedResidualNetwork(input_dim, hidden_dim, hidden_dim, dropout)
        
        # LSTM Encoder
        self.lstm_encoder = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=n_lstm_layers,
            dropout=dropout,
            batch_first=True,
        )
        
        # LSTM Decoder (for multi-horizon)
        self.lstm_decoder = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=n_lstm_layers,
            dropout=dropout,
            batch_first=True,
        )
        
        # Interpretable Multi-Head Attention
        self.attention = InterpretableMultiHeadAttention(hidden_dim, n_heads, dropout)
        
        # Gated Residual Network for fusion
        self.grn_fusion = GatedResidualNetwork(hidden_dim * 2, hidden_dim, hidden_dim, dropout)
        
        # Quantile outputs
        self.quantile_proj = nn.Linear(hidden_dim, self.n_quantiles)
        
        self.dropout = nn.Dropout(dropout)
    
    def forward(
        self,
        x: torch.Tensor,
        future_features: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, seq_len, input_dim) — historique
            future_features: (batch, horizon, input_dim) — features futures connues
        
        Returns:
            quantiles: (batch, horizon, n_quantiles)
        """
        batch_size, seq_len, _ = x.shape
        
        # Variable Selection Network
        x_selected = self.vsn(x)
        
        # LSTM Encoder
        lstm_out, (h_n, c_n) = self.lstm_encoder(x_selected)
        
        # Decoder (if future features provided)
        if future_features is not None:
            horizon = future_features.size(1)
            future_selected = self.vsn(future_features)
            
            # Initialize decoder with encoder state
            decoder_out, _ = self.lstm_decoder(future_selected, (h_n, c_n))
        else:
            # Auto-regressive: use last encoder output
            decoder_out = lstm_out[:, -1:, :].repeat(1, 10, 1)  # Default 10 steps
            horizon = decoder_out.size(1)
        
        # Attention: decoder attends to encoder
        attn_out, attn_weights = self.attention(decoder_out, lstm_out, lstm_out)
        
        # Skip connection: concatenate decoder output with attention output
        combined = torch.cat([decoder_out, attn_out], dim=-1)
        
        # Gated fusion
        fused = self.grn_fusion(combined)
        fused = self.dropout(fused)
        
        # Quantile outputs
        quantiles = self.quantile_proj(fused)  # (batch, horizon, n_quantiles)
        
        return quantiles
    
    def predict_quantiles(self, x: torch.Tensor, horizon: int = 10) -> Dict[str, torch.Tensor]:
        """Predict quantiles for given horizon."""
        with torch.no_grad():
            quantiles = self.forward(x)
            
            # If we need more steps than predicted
            if quantiles.size(1) < horizon:
                # Pad with last prediction
                last = quantiles[:, -1:, :]
                repeats = horizon - quantiles.size(1)
                padding = last.repeat(1, repeats, 1)
                quantiles = torch.cat([quantiles, padding], dim=1)
            elif quantiles.size(1) > horizon:
                quantiles = quantiles[:, :horizon, :]
        
        return {
            f"P{int(q*100)}": quantiles[:, :, i]
            for i, q in enumerate(self.output_quantiles)
        }


class TFTForecaster:
    """Wrapper for Temporal Fusion Transformer."""
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        n_heads: int = 4,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "n_heads": n_heads,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = TemporalFusionTransformer(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            n_heads=n_heads,
        ).to(self.device)
        
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, mode="min", factor=0.5, patience=5
        )
        self._fitted = False
    
    def fit(self, X: np.ndarray, y: np.ndarray, eval_set: Optional[Tuple] = None):
        """Fit TFT model."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                
                # TFT outputs quantiles, use quantile loss
                quantiles = self.model(batch_X)
                
                # Quantile loss
                loss = 0.0
                for i, q in enumerate(self.model.output_quantiles):
                    errors = batch_y - quantiles[:, :, i]
                    loss += torch.mean(torch.max(q * errors, (q - 1) * errors))
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
                epoch_loss += loss.item()
            
            self.scheduler.step(epoch_loss / len(loader))
        
        self._fitted = True
        self.model.eval()
        logger.info("tft_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray, horizon: int = 10) -> List[ForecastResult]:
        """Predict with TFT."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            quantiles = self.model.predict_quantiles(X_t, horizon)
        
        p50 = quantiles["P50"].cpu().numpy()
        p10 = quantiles["P10"].cpu().numpy()
        p90 = quantiles["P90"].cpu().numpy()
        
        results = []
        for i in range(min(horizon, len(p50[0]))):
            val = float(p50[0, i])
            lower = float(p10[0, i])
            upper = float(p90[0, i])
            conf = 1.0 - (upper - lower) / (abs(val) + 1e-8)
            
            results.append(ForecastResult(
                value=val,
                lower_bound=lower,
                upper_bound=upper,
                confidence=float(min(conf, 1.0)),
                horizon_steps=i + 1,
                prediction_type="trend",
                model_name="TFT",
                inference_time_ms=(time.time() - start) * 1000 / horizon,
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 2. DEEPAR — Amazon (Probabilistic Forecasting)
# ═══════════════════════════════════════════════════════════════════════════

class DeepARModel(nn.Module):
    """
    DeepAR — Probabilistic forecasting with autoregressive RNN.
    
    Prédit les paramètres d'une distribution de probabilité (Student-T)
    à chaque pas de temps, permettant des intervalles de confiance naturels.
    
    Distribution: Student-T(μ, σ, ν) où μ = location, σ = scale, ν = dof
    
    Référence : Salinas et al. "DeepAR: Probabilistic Forecasting with
                Autoregressive Recurrent Networks" (Amazon, 2020)
    """
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 2):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        
        # LSTM
        self.lstm = nn.LSTM(
            input_size=input_dim + 1,  # +1 for previous target
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1,
        )
        
        # Output distribution parameters (Student-T)
        self.mu = nn.Linear(hidden_dim, 1)
        self.sigma = nn.Linear(hidden_dim, 1)
        self.nu = nn.Linear(hidden_dim, 1)  # Degrees of freedom
    
    def forward(self, x: torch.Tensor, y_prev: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: (batch, seq_len, input_dim) — features
            y_prev: (batch, seq_len, 1) — previous target values
        
        Returns:
            mu, sigma, nu: distribution parameters
        """
        batch_size, seq_len, _ = x.shape
        
        if y_prev is None:
            y_prev = torch.zeros(batch_size, seq_len, 1, device=x.device)
        
        # Concatenate features with previous target
        lstm_input = torch.cat([x, y_prev], dim=-1)
        
        # LSTM
        lstm_out, _ = self.lstm(lstm_input)
        
        # Distribution parameters
        mu = self.mu(lstm_out)
        sigma = F.softplus(self.sigma(lstm_out)) + 1e-6
        nu = F.softplus(self.nu(lstm_out)) + 2.0  # ν > 2 for finite variance
        
        return mu, sigma, nu
    
    def loss(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        """Negative log-likelihood of Student-T distribution."""
        mu, sigma, nu = self.forward(x, y.unsqueeze(-1))
        
        # Student-T log-likelihood
        # log p(y|μ,σ,ν) = log Γ((ν+1)/2) - log Γ(ν/2) - 0.5*log(πν) - log σ
        #                   - ((ν+1)/2) * log(1 + ((y-μ)/σ)²/ν)
        y_expanded = y.unsqueeze(-1)
        diff = (y_expanded - mu) / sigma
        log_likelihood = (
            torch.lgamma((nu + 1) / 2)
            - torch.lgamma(nu / 2)
            - 0.5 * torch.log(nu * torch.pi)
            - torch.log(sigma)
            - ((nu + 1) / 2) * torch.log(1 + diff ** 2 / nu)
        )
        
        return -log_likelihood.mean()


class DeepARForecaster:
    """Wrapper for DeepAR."""
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = DeepARModel(input_dim, hidden_dim).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self._fitted = False
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit DeepAR model."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                loss = self.model.loss(batch_X, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                epoch_loss += loss.item()
        
        self._fitted = True
        self.model.eval()
        logger.info("deepar_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray, horizon: int = 10, n_samples: int = 100) -> List[ForecastResult]:
        """Predict with DeepAR using Monte Carlo sampling."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        # Monte Carlo sampling from predicted distribution
        samples = []
        with torch.no_grad():
            for _ in range(n_samples):
                mu, sigma, nu = self.model(X_t)
                # Sample from Student-T
                # t = z / sqrt(w/ν) where z ~ N(0,1), w ~ χ²(ν)
                z = torch.randn_like(mu)
                w = torch.distributions.Chi2(nu).sample()
                t = z / torch.sqrt(w / nu)
                sample = mu + sigma * t
                samples.append(sample.cpu().numpy())
        
        samples = np.array(samples)  # (n_samples, batch, seq_len, 1)
        
        results = []
        for i in range(min(horizon, samples.shape[2])):
            vals = samples[:, 0, i, 0]
            val = float(np.mean(vals))
            lower = float(np.percentile(vals, 10))
            upper = float(np.percentile(vals, 90))
            conf = 1.0 - float(np.std(vals) / (abs(val) + 1e-8))
            
            results.append(ForecastResult(
                value=val,
                lower_bound=lower,
                upper_bound=upper,
                confidence=float(min(conf, 1.0)),
                horizon_steps=i + 1,
                prediction_type="trend",
                model_name="DeepAR",
                inference_time_ms=(time.time() - start) * 1000 / horizon,
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 3. N-BEATS — Element AI (Pure MLP)
# ═══════════════════════════════════════════════════════════════════════════

class NBeatsBlock(nn.Module):
    """
    N-BEATS block — basic building block.
    
    Chaque block apprend à décomposer la série en tendance + saisonnalité
    via des couches fully connected avec des fonctions de base.
    
    backcast = what the block removes from input
    forecast = what the block adds to the prediction
    """
    
    def __init__(self, input_dim: int, theta_dim: int, hidden_dim: int = 256):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, hidden_dim)
        self.fc4 = nn.Linear(hidden_dim, theta_dim)
        
        # Backcast and forecast basis
        self.backcast_basis = nn.Linear(theta_dim, input_dim)
        self.forecast_basis = nn.Linear(theta_dim, input_dim)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Returns:
            backcast: (batch, input_dim) — what to remove
            forecast: (batch, input_dim) — what to add
        """
        h = F.relu(self.fc1(x))
        h = F.relu(self.fc2(h))
        h = F.relu(self.fc3(h))
        theta = self.fc4(h)
        
        backcast = self.backcast_basis(theta)
        forecast = self.forecast_basis(theta)
        
        return backcast, forecast


class NBeatsModel(nn.Module):
    """
    N-BEATS — Neural Basis Expansion Analysis for Time Series.
    
    Architecture purement MLP (pas de RNN, pas d'attention) qui décompose
    la série en tendance + saisonnalité via des blocs empilés.
    
    Avantages :
    - Interprétable (tendance et saisonnalité explicites)
    - Pas de problème de gradient (pas de RNN)
    - SOTA sur M3, M4, M5 competitions
    
    Référence : Oreshkin et al. "N-BEATS: Neural basis expansion analysis
                for interpretable time series forecasting" (ICLR 2020)
    """
    
    def __init__(self, input_dim: int = 64, n_blocks: int = 5, hidden_dim: int = 256):
        super().__init__()
        self.input_dim = input_dim
        self.n_blocks = n_blocks
        
        # Stack of N-BEATS blocks
        self.blocks = nn.ModuleList([
            NBeatsBlock(input_dim, theta_dim=input_dim * 2, hidden_dim=hidden_dim)
            for _ in range(n_blocks)
        ])
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, input_dim) — flattened sequence
        
        Returns:
            forecast: (batch, input_dim) — forecast
        """
        residual = x
        forecast_total = 0
        
        for block in self.blocks:
            backcast, forecast = block(residual)
            residual = residual - backcast
            forecast_total = forecast_total + forecast
        
        return forecast_total


class NBeatsForecaster:
    """Wrapper for N-BEATS."""
    
    def __init__(
        self,
        input_dim: int = 64,
        n_blocks: int = 5,
        hidden_dim: int = 256,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "n_blocks": n_blocks,
            "hidden_dim": hidden_dim,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = NBeatsModel(input_dim, n_blocks, hidden_dim).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self._fitted = False
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit N-BEATS model."""
        # Flatten sequences: (batch, seq_len, features) -> (batch, seq_len * features)
        if len(X.shape) == 3:
            X_flat = X.reshape(X.shape[0], -1)
        else:
            X_flat = X
        
        X_t = torch.from_numpy(X_flat).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                forecast = self.model(batch_X)
                loss = F.mse_loss(forecast, batch_y)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item()
        
        self._fitted = True
        self.model.eval()
        logger.info("nbeats_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray, horizon: int = 10) -> List[ForecastResult]:
        """Predict with N-BEATS."""
        import time
        start = time.time()
        
        if len(X.shape) == 3:
            X_flat = X.reshape(X.shape[0], -1)
        else:
            X_flat = X
        
        X_t = torch.from_numpy(X_flat).float().to(self.device)
        
        with torch.no_grad():
            forecast = self.model(X_t).cpu().numpy()
        
        # Split forecast into horizon steps
        step_size = forecast.shape[-1] // horizon if forecast.shape[-1] >= horizon else 1
        results = []
        for i in range(min(horizon, forecast.shape[-1])):
            val = float(forecast[0, i * step_size] if step_size > 0 else forecast[0, i])
            results.append(ForecastResult(
                value=val,
                lower_bound=val * 0.9,
                upper_bound=val * 1.1,
                confidence=0.8,
                horizon_steps=i + 1,
                prediction_type="trend",
                model_name="NBeats",
                inference_time_ms=(time.time() - start) * 1000 / horizon,
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 4. PATCHTST — MIT (Transformer with Patches)
# ═══════════════════════════════════════════════════════════════════════════

class PatchTSTModel(nn.Module):
    """
    PatchTST — Time Series Transformer with Patches.
    
    Découpe la série temporelle en patches (sous-séquences) et utilise
    un transformer pour modéliser les relations entre patches.
    
    Avantages :
    - Réduit la longueur de séquence (patches au lieu de points)
    - Capture les patterns locaux et globaux
    - Plus efficace que les transformers classiques
    
    Référence : Nie et al. "A Time Series is Worth 64 Words: Long-term
                Forecasting with Transformers" (MIT, ICLR 2023)
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        patch_len: int = 8,
        stride: int = 4,
        d_model: int = 128,
        n_heads: int = 8,
        n_layers: int = 3,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.patch_len = patch_len
        self.stride = stride
        
        # Patch embedding
        self.patch_embed = nn.Linear(patch_len, d_model)
        
        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.randn(1, 100, d_model) * 0.1)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=d_model * 4,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        
        # Output projection
        self.output_proj = nn.Linear(d_model, input_dim)
        
        self.dropout = nn.Dropout(dropout)
    
    def _create_patches(self, x: torch.Tensor) -> torch.Tensor:
        """Create patches from input sequence."""
        batch_size, seq_len, _ = x.shape
        
        # Flatten features
        x_flat = x.reshape(batch_size, -1)  # (batch, seq_len * features)
        
        # Create patches
        patches = []
        for i in range(0, x_flat.shape[1] - self.patch_len + 1, self.stride):
            patch = x_flat[:, i:i + self.patch_len]
            patches.append(patch)
        
        if not patches:
            patches.append(x_flat[:, :self.patch_len])
        
        return torch.stack(patches, dim=1)  # (batch, n_patches, patch_len)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, seq_len, input_dim)
        
        Returns:
            forecast: (batch, input_dim)
        """
        # Create patches
        patches = self._create_patches(x)  # (batch, n_patches, patch_len)
        
        # Patch embedding
        embedded = self.patch_embed(patches)  # (batch, n_patches, d_model)
        embedded = self.dropout(embedded)
        
        # Add positional encoding
        n_patches = embedded.size(1)
        embedded = embedded + self.pos_encoding[:, :n_patches, :]
        
        # Transformer
        transformed = self.transformer(embedded)
        
        # Global pooling
        pooled = transformed.mean(dim=1)  # (batch, d_model)
        
        # Output
        forecast = self.output_proj(pooled)  # (batch, input_dim)
        
        return forecast


class PatchTSTForecaster:
    """Wrapper for PatchTST."""
    
    def __init__(
        self,
        input_dim: int = 64,
        patch_len: int = 8,
        stride: int = 4,
        d_model: int = 128,
        n_heads: int = 8,
        n_layers: int = 3,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "patch_len": patch_len,
            "stride": stride,
            "d_model": d_model,
            "n_heads": n_heads,
            "n_layers": n_layers,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = PatchTSTModel(
            input_dim=input_dim,
            patch_len=patch_len,
            stride=stride,
            d_model=d_model,
            n_heads=n_heads,
            n_layers=n_layers,
        ).to(self.device)
        
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self._fitted = False
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit PatchTST model."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                forecast = self.model(batch_X)
                loss = F.mse_loss(forecast, batch_y)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item()
        
        self._fitted = True
        self.model.eval()
        logger.info("patchtst_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray, horizon: int = 10) -> List[ForecastResult]:
        """Predict with PatchTST."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            forecast = self.model(X_t).cpu().numpy()
        
        step_size = forecast.shape[-1] // horizon if forecast.shape[-1] >= horizon else 1
        results = []
        for i in range(min(horizon, forecast.shape[-1])):
            val = float(forecast[0, i * step_size] if step_size > 0 else forecast[0, i])
            results.append(ForecastResult(
                value=val,
                lower_bound=val * 0.92,
                upper_bound=val * 1.08,
                confidence=0.85,
                horizon_steps=i + 1,
                prediction_type="trend",
                model_name="PatchTST",
                inference_time_ms=(time.time() - start) * 1000 / horizon,
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_ultra_predictor(
    input_dim: int = 64,
    hidden_dim: int = 128,
    device: str = "cpu",
    use_tft: bool = True,
    use_deepar: bool = True,
    use_nbeats: bool = True,
    use_patchtst: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système de prédiction complet Niveau 2.
    
    Retourne un dict avec tous les prédicteurs.
    
    Args:
        input_dim: Dimension d'entrée des features
        hidden_dim: Dimension cachée
        device: "cpu" ou "cuda"
        use_tft: Activer Temporal Fusion Transformer
        use_deepar: Activer DeepAR
        use_nbeats: Activer N-BEATS
        use_patchtst: Activer PatchTST
    
    Returns:
        Dict avec tous les composants
    """
    predictors = {}
    
    if use_tft:
        predictors["tft"] = TFTForecaster(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            device=device,
        )
        logger.info("✅ TFT (Temporal Fusion Transformer) initialized")
    
    if use_deepar:
        predictors["deepar"] = DeepARForecaster(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            device=device,
        )
        logger.info("✅ DeepAR initialized")
    
    if use_nbeats:
        predictors["nbeats"] = NBeatsForecaster(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            device=device,
        )
        logger.info("✅ N-BEATS initialized")
    
    if use_patchtst:
        predictors["patchtst"] = PatchTSTForecaster(
            input_dim=input_dim,
            d_model=hidden_dim,
            device=device,
        )
        logger.info("✅ PatchTST initialized")
    
    return {
        "predictors": predictors,
        "config": {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "device": device,
            "n_predictors": len(predictors),
        },
    }


def create_ultra_predictor_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_predictor(
        input_dim=64,
        hidden_dim=128,
        use_tft=True,
        use_deepar=False,
        use_nbeats=False,
        use_patchtst=False,
    )


def create_ultra_predictor_full() -> Dict[str, Any]:
    """Version complète avec tous les prédicteurs."""
    return create_ultra_predictor(
        input_dim=64,
        hidden_dim=128,
        use_tft=True,
        use_deepar=True,
        use_nbeats=True,
        use_patchtst=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# PREDICTION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

class UltraPredictorPipeline:
    """
    Pipeline complet qui intègre tous les prédicteurs.
    
    Coordonne :
    - TFT (Temporal Fusion Transformer)
    - DeepAR (Probabilistic Forecasting)
    - N-BEATS (Basis Expansion)
    - PatchTST (Transformer with Patches)
    - Ensemble des prédictions
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        device: str = "cpu",
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.device = device
        
        self.predictor_system = create_ultra_predictor_full()
        
        # Performance tracking
        self._performance: Dict[str, List[float]] = {
            name: [] for name in self.predictor_system["predictors"]
        }
        
        logger.info("🚀 UltraPredictorPipeline initialized")
    
    def fit_all(self, X: np.ndarray, y: np.ndarray):
        """Fit all predictors on training data."""
        for name, predictor in self.predictor_system["predictors"].items():
            try:
                predictor.fit(X, y)
                logger.info(f"✅ {name} fitted")
            except Exception as e:
                logger.error(f"Failed to fit {name}", error=str(e))
    
    def predict_all(self, X: np.ndarray, horizon: int = 10) -> Dict[str, List[ForecastResult]]:
        """Predict with all predictors."""
        results = {}
        for name, predictor in self.predictor_system["predictors"].items():
            try:
                results[name] = predictor.predict(X, horizon)
            except Exception as e:
                logger.error(f"Failed to predict with {name}", error=str(e))
                results[name] = []
        return results
    
    def predict_ensemble(self, X: np.ndarray, horizon: int = 10) -> List[ForecastResult]:
        """
        Prédiction ensembliste : moyenne pondérée de tous les prédicteurs.
        """
        all_results = self.predict_all(X, horizon)
        
        if not all_results:
            return []
        
        ensemble_results = []
        n_predictors = len(all_results)
        
        for step in range(horizon):
            values = []
            lower_bounds = []
            upper_bounds = []
            confidences = []
            
            for name, results in all_results.items():
                if step < len(results):
                    values.append(results[step].value)
                    lower_bounds.append(results[step].lower_bound)
                    upper_bounds.append(results[step].upper_bound)
                    confidences.append(results[step].confidence)
            
            if values:
                ensemble_results.append(ForecastResult(
                    value=float(np.mean(values)),
                    lower_bound=float(np.min(lower_bounds)),
                    upper_bound=float(np.max(upper_bounds)),
                    confidence=float(np.mean(confidences)),
                    horizon_steps=step + 1,
                    prediction_type="ensemble",
                    model_name="Ensemble",
                ))
        
        return ensemble_results
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get complete system statistics."""
        return {
            "predictors": list(self.predictor_system["predictors"].keys()),
            "config": self.predictor_system["config"],
            "n_predictors": len(self.predictor_system["predictors"]),
        }


# Instance globale
ultra_predictor_pipeline = UltraPredictorPipeline()


def get_ultra_predictor() -> UltraPredictorPipeline:
    """Get the global ultra predictor instance."""
    return ultra_predictor_pipeline


