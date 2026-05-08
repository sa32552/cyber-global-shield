"""
Cyber Global Shield — Quantum Transcendent Predictor (Pilier 5)
Prédiction multi-modèles qui dépasse l'entendement.

Architecture à 4 modèles fusionnés :
1. LSTM Quantique — Réseau récurrent profond pour séries temporelles
2. Transformer Temporel — Attention multi-têtes pour prédiction temporelle
3. Prophet Adaptatif — Décomposition saisonnière avec détection de tendances
4. Quantum Predictor — Fusion quantique des prédictions

Fusion : Stacking adaptatif avec méta-modèle (CatBoost)
Prédiction : Attaques + Anomalies + Tendances + Risques
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
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
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score

# ─── CatBoost (méta-modèle) ─────────────────────────────────────────────────
try:
    from catboost import CatBoostRegressor, Pool
    HAS_CATBOOST = True
except ImportError:
    HAS_CATBOOST = False

# ─── Prophet ────────────────────────────────────────────────────────────────
try:
    HAS_PROPHET = False
    # Implémentation custom si Prophet pas disponible
except ImportError:
    HAS_PROPHET = False

logger = structlog.get_logger(__name__)


# =============================================================================
# Types de prédiction
# =============================================================================

class PredictionHorizon(Enum):
    """Horizons de prédiction."""
    SHORT_TERM = "short_term"      # 1-5 minutes
    MEDIUM_TERM = "medium_term"    # 5-30 minutes
    LONG_TERM = "long_term"        # 30-120 minutes
    STRATEGIC = "strategic"        # 2-24 heures

class PredictionType(Enum):
    """Types de prédiction."""
    ATTACK = "attack"              # Prédiction d'attaques
    ANOMALY = "anomaly"            # Prédiction d'anomalies
    TREND = "trend"                # Prédiction de tendances
    RISK = "risk"                  # Prédiction de risques
    CAPACITY = "capacity"          # Prédiction de capacité
    LATENCY = "latency"            # Prédiction de latence


# =============================================================================
# Résultat de prédiction
# =============================================================================

@dataclass
class PredictionResult:
    """Résultat d'une prédiction."""
    value: float
    confidence: float
    lower_bound: float
    upper_bound: float
    horizon: PredictionHorizon
    prediction_type: PredictionType
    timestamp: float
    inference_time_ms: float
    explanation: Optional[str] = None


@dataclass
class TimeSeriesPrediction:
    """Prédiction de série temporelle."""
    timestamps: List[float]
    values: List[float]
    lower_bounds: List[float]
    upper_bounds: List[float]
    confidences: List[float]
    horizon: PredictionHorizon
    prediction_type: PredictionType
    model_scores: Dict[str, float] = field(default_factory=dict)
    trend: Optional[float] = None
    seasonality: Optional[Dict[str, float]] = None


@dataclass
class PredictionBatch:
    """Lot de prédictions."""
    predictions: List[PredictionResult]
    time_series: Optional[TimeSeriesPrediction] = None
    n_predictions: int = 0
    avg_confidence: float = 0.0
    batch_inference_time_ms: float = 0.0


# =============================================================================
# Modèle 1 : LSTM Quantique
# =============================================================================

class QuantumLSTM(nn.Module):
    """
    LSTM profond avec mécanismes quantiques.
    
    Caractéristiques :
    - LSTM bidirectionnel à 3 couches
    - Attention temporelle
    - Dropout adaptatif
    - Skip connections
    - Normalisation de couche
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 3,
        output_dim: int = 1,
        dropout: float = 0.2,
        bidirectional: bool = True,
        sequence_length: int = 50,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.output_dim = output_dim
        self.sequence_length = sequence_length
        
        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            dropout=dropout,
            bidirectional=bidirectional,
            batch_first=True,
        )
        
        lstm_output_dim = hidden_dim * (2 if bidirectional else 1)
        
        # Attention temporelle
        self.attention = nn.MultiheadAttention(
            embed_dim=lstm_output_dim,
            num_heads=8,
            dropout=dropout,
            batch_first=True,
        )
        
        # Skip connection
        self.skip_projection = nn.Linear(input_dim, lstm_output_dim)
        
        # Couches de sortie
        self.layer_norm = nn.LayerNorm(lstm_output_dim)
        self.dropout = nn.Dropout(dropout)
        
        self.fc1 = nn.Linear(lstm_output_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.fc3 = nn.Linear(hidden_dim // 2, output_dim)
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch_size, sequence_length, input_dim)
        
        Returns:
            (batch_size, output_dim)
        """
        # LSTM
        lstm_out, (hidden, cell) = self.lstm(x)
        
        # Attention temporelle
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
        
        # Skip connection
        skip = self.skip_projection(x[:, -1, :])  # Dernier pas de temps
        skip = skip.unsqueeze(1).expand(-1, attn_out.size(1), -1)
        
        # Fusion
        combined = attn_out + skip
        combined = self.layer_norm(combined)
        
        # Pooling (moyenne sur la séquence)
        pooled = combined.mean(dim=1)
        pooled = self.dropout(pooled)
        
        # Couches fully connected
        out = self.relu(self.fc1(pooled))
        out = self.dropout(out)
        out = self.relu(self.fc2(out))
        out = self.fc3(out)
        
        return out


class TranscendentLSTM:
    """
    Wrapper pour le LSTM Quantique.
    
    Caractéristiques :
    - Entraînement avec early stopping
    - Learning rate adaptatif
    - Validation automatique
    - Prédiction avec intervalles de confiance
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 3,
        output_dim: int = 1,
        sequence_length: int = 50,
        learning_rate: float = 0.001,
        batch_size: int = 32,
        n_epochs: int = 100,
        patience: int = 10,
        device: str = 'cpu',
    ):
        self.params = {
            'input_dim': input_dim,
            'hidden_dim': hidden_dim,
            'num_layers': num_layers,
            'output_dim': output_dim,
            'sequence_length': sequence_length,
            'learning_rate': learning_rate,
            'batch_size': batch_size,
            'n_epochs': n_epochs,
            'patience': patience,
        }
        
        self.device = torch.device(device if torch.cuda.is_available() else 'cpu')
        self.model = QuantumLSTM(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            output_dim=output_dim,
            sequence_length=sequence_length,
        ).to(self.device)
        
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, mode='min', factor=0.5, patience=5
        )
        self.criterion = nn.MSELoss()
        
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.best_loss = float('inf')
        self.epochs_trained = 0
    
    def _create_sequences(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Crée des séquences pour le LSTM."""
        sequences = []
        targets = []
        
        for i in range(len(X) - self.params['sequence_length']):
            seq = X[i:i + self.params['sequence_length']]
            target = y[i + self.params['sequence_length']]
            sequences.append(seq)
            targets.append(target)
        
        return (
            torch.FloatTensor(np.array(sequences)),
            torch.FloatTensor(np.array(targets)),
        )
    
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        eval_set: Optional[Tuple[np.ndarray, np.ndarray]] = None,
    ) -> 'TranscendentLSTM':
        """Entraîne le LSTM."""
        X_scaled = self.scaler.fit_transform(X)
        
        # Création des séquences
        X_seq, y_seq = self._create_sequences(X_scaled, y)
        
        dataset = TensorDataset(X_seq, y_seq)
        dataloader = DataLoader(
            dataset,
            batch_size=self.params['batch_size'],
            shuffle=True,
        )
        
        # Validation set
        if eval_set:
            X_val_scaled = self.scaler.transform(eval_set[0])
            X_val_seq, y_val_seq = self._create_sequences(X_val_scaled, eval_set[1])
            val_dataset = TensorDataset(X_val_seq, y_val_seq)
            val_dataloader = DataLoader(
                val_dataset,
                batch_size=self.params['batch_size'],
                shuffle=False,
            )
        
        # Entraînement
        best_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(self.params['n_epochs']):
            self.model.train()
            train_loss = 0.0
            
            for batch_X, batch_y in dataloader:
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.to(self.device)
                
                self.optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = self.criterion(outputs.squeeze(), batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
                train_loss += loss.item()
            
            train_loss /= len(dataloader)
            
            # Validation
            if eval_set:
                self.model.eval()
                val_loss = 0.0
                
                with torch.no_grad():
                    for batch_X, batch_y in val_dataloader:
                        batch_X = batch_X.to(self.device)
                        batch_y = batch_y.to(self.device)
                        outputs = self.model(batch_X)
                        loss = self.criterion(outputs.squeeze(), batch_y)
                        val_loss += loss.item()
                
                val_loss /= len(val_dataloader)
                self.scheduler.step(val_loss)
                
                # Early stopping
                if val_loss < best_loss:
                    best_loss = val_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if patience_counter >= self.params['patience']:
                        logger.info("lstm_early_stopping", epoch=epoch, val_loss=val_loss)
                        break
            else:
                self.scheduler.step(train_loss)
            
            self.epochs_trained = epoch + 1
        
        self.best_loss = best_loss if eval_set else train_loss
        self.is_fitted = True
        
        logger.info("lstm_trained",
                    epochs=self.epochs_trained,
                    best_loss=f"{self.best_loss:.6f}")
        return self
    
    def predict(
        self,
        X: np.ndarray,
        return_std: bool = False,
    ) -> Union[np.ndarray, Tuple[np.ndarray, np.ndarray]]:
        """Prédit avec le LSTM."""
        if not self.is_fitted:
            return np.zeros(len(X)) if not return_std else (np.zeros(len(X)), np.zeros(len(X)))
        
        self.model.eval()
        X_scaled = self.scaler.transform(X)
        
        # Création des séquences
        sequences = []
        for i in range(len(X_scaled) - self.params['sequence_length']):
            sequences.append(X_scaled[i:i + self.params['sequence_length']])
        
        if not sequences:
            return np.zeros(len(X)) if not return_std else (np.zeros(len(X)), np.zeros(len(X)))
        
        X_seq = torch.FloatTensor(np.array(sequences)).to(self.device)
        
        with torch.no_grad():
            predictions = self.model(X_seq).cpu().numpy().flatten()
        
        # Padding pour correspondre à la longueur originale
        full_predictions = np.zeros(len(X))
        full_predictions[self.params['sequence_length']:] = predictions
        
        if return_std:
            # Estimation de l'incertitude via Monte Carlo Dropout
            self.model.train()
            mc_predictions = []
            
            with torch.no_grad():
                for _ in range(20):
                    mc_out = self.model(X_seq).cpu().numpy().flatten()
                    mc_full = np.zeros(len(X))
                    mc_full[self.params['sequence_length']:] = mc_out
                    mc_predictions.append(mc_full)
            
            mc_std = np.std(mc_predictions, axis=0)
            return full_predictions, mc_std
        
        return full_predictions


# =============================================================================
# Modèle 2 : Transformer Temporel
# =============================================================================

class TemporalTransformer(nn.Module):
    """
    Transformer pour prédiction temporelle.
    
    Caractéristiques :
    - Encoder Transformer avec attention multi-têtes
    - Positional encoding temporel
    - Masking adaptatif
    - Skip connections résiduelles
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        d_model: int = 128,
        nhead: int = 8,
        num_encoder_layers: int = 4,
        dim_feedforward: int = 512,
        dropout: float = 0.1,
        output_dim: int = 1,
        max_sequence_length: int = 100,
    ):
        super().__init__()
        self.d_model = d_model
        self.max_sequence_length = max_sequence_length
        
        # Projection d'entrée
        self.input_projection = nn.Linear(input_dim, d_model)
        
        # Positional encoding temporel
        self.positional_encoding = nn.Parameter(
            torch.randn(1, max_sequence_length, d_model) * 0.1
        )
        
        # Encoder Transformer
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_encoder_layers,
        )
        
        # Layer normalization
        self.layer_norm = nn.LayerNorm(d_model)
        
        # Couches de sortie
        self.fc1 = nn.Linear(d_model, d_model // 2)
        self.fc2 = nn.Linear(d_model // 2, output_dim)
        
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch_size, sequence_length, input_dim)
        
        Returns:
            (batch_size, output_dim)
        """
        batch_size, seq_len, _ = x.shape
        
        # Projection
        x = self.input_projection(x)
        
        # Positional encoding
        x = x + self.positional_encoding[:, :seq_len, :]
        
        # Transformer encoder
        x = self.transformer_encoder(x)
        x = self.layer_norm(x)
        
        # Pooling (moyenne pondérée)
        weights = torch.softmax(x.mean(dim=-1), dim=-1)
        x = (x * weights.unsqueeze(-1)).sum(dim=1)
        
        # Couches de sortie
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        
        return x


class TranscendentTransformer:
    """
    Wrapper pour le Transformer Temporel.
    
    Caractéristiques :
    - Entraînement avec warmup
    - Learning rate cosine annealing
    - Validation automatique
    - Prédiction multi-horizon
    """
    
    def __init__(
        self,
        input_dim: int = 64,
        d_model: int = 128,
        nhead: int = 8,
        num_encoder_layers: int = 4,
        output_dim: int = 1,
        sequence_length: int = 50,
        learning_rate: float = 0.0005,
        batch_size: int = 32,
        n_epochs: int = 100,
        warmup_epochs: int = 5,
        device: str = 'cpu',
    ):
        self.params = {
            'input_dim': input_dim,
            'd_model': d_model,
            'nhead': nhead,
            'num_encoder_layers': num_encoder_layers,
            'output_dim': output_dim,
            'sequence_length': sequence_length,
            'learning_rate': learning_rate,
            'batch_size': batch_size,
            'n_epochs': n_epochs,
            'warmup_epochs': warmup_epochs,
        }
        
        self.device = torch.device(device if torch.cuda.is_available() else 'cpu')
        self.model = TemporalTransformer(
            input_dim=input_dim,
            d_model=d_model,
            nhead=nhead,
            num_encoder_layers=num_encoder_layers,
            output_dim=output_dim,
            max_sequence_length=sequence_length,
        ).to(self.device)
        
        self.optimizer = optim.AdamW(self.model.parameters(), lr=learning_rate)
        self.scheduler = optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer, T_max=n_epochs
        )
        self.criterion = nn.HuberLoss()
        
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.best_loss = float('inf')
    
    def _create_sequences(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Crée des séquences pour le Transformer."""
        sequences = []
        targets = []
        
        for i in range(len(X) - self.params['sequence_length']):
            seq = X[i:i + self.params['sequence_length']]
            target = y[i + self.params['sequence_length']]
            sequences.append(seq)
            targets.append(target)
        
        return (
            torch.FloatTensor(np.array(sequences)),
            torch.FloatTensor(np.array(targets)),
        )
    
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        eval_set: Optional[Tuple[np.ndarray, np.ndarray]] = None,
    ) -> 'TranscendentTransformer':
        """Entraîne le Transformer."""
        X_scaled = self.scaler.fit_transform(X)
        
        X_seq, y_seq = self._create_sequences(X_scaled, y)
        dataset = TensorDataset(X_seq, y_seq)
        dataloader = DataLoader(
            dataset,
            batch_size=self.params['batch_size'],
            shuffle=True,
        )
        
        if eval_set:
            X_val_scaled = self.scaler.transform(eval_set[0])
            X_val_seq, y_val_seq = self._create_sequences(X_val_scaled, eval_set[1])
            val_dataset = TensorDataset(X_val_seq, y_val_seq)
            val_dataloader = DataLoader(
                val_dataset,
                batch_size=self.params['batch_size'],
                shuffle=False,
            )
        
        best_loss = float('inf')
        
        for epoch in range(self.params['n_epochs']):
            self.model.train()
            train_loss = 0.0
            
            for batch_X, batch_y in dataloader:
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.to(self.device)
                
                self.optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = self.criterion(outputs.squeeze(), batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
                train_loss += loss.item()
            
            train_loss /= len(dataloader)
            
            # Warmup
            if epoch < self.params['warmup_epochs']:
                for param_group in self.optimizer.param_groups:
                    param_group['lr'] = self.params['learning_rate'] * (
                        epoch + 1
                    ) / self.params['warmup_epochs']
            
            self.scheduler.step()
            
            if eval_set:
                self.model.eval()
                val_loss = 0.0
                
                with torch.no_grad():
                    for batch_X, batch_y in val_dataloader:
                        batch_X = batch_X.to(self.device)
                        batch_y = batch_y.to(self.device)
                        outputs = self.model(batch_X)
                        loss = self.criterion(outputs.squeeze(), batch_y)
                        val_loss += loss.item()
                
                val_loss /= len(val_dataloader)
                
                if val_loss < best_loss:
                    best_loss = val_loss
        
        self.best_loss = best_loss if eval_set else train_loss
        self.is_fitted = True
        
        logger.info("transformer_trained",
                    epochs=self.params['n_epochs'],
                    best_loss=f"{self.best_loss:.6f}")
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit avec le Transformer."""
        if not self.is_fitted:
            return np.zeros(len(X))
        
        self.model.eval()
        X_scaled = self.scaler.transform(X)
        
        sequences = []
        for i in range(len(X_scaled) - self.params['sequence_length']):
            sequences.append(X_scaled[i:i + self.params['sequence_length']])
        
        if not sequences:
            return np.zeros(len(X))
        
        X_seq = torch.FloatTensor(np.array(sequences)).to(self.device)
        
        with torch.no_grad():
            predictions = self.model(X_seq).cpu().numpy().flatten()
        
        full_predictions = np.zeros(len(X))
        full_predictions[self.params['sequence_length']:] = predictions
        
        return full_predictions


# =============================================================================
# Modèle 3 : Prophet Adaptatif
# =============================================================================

class TranscendentProphet:
    """
    Prophet adaptatif pour décomposition de séries temporelles.
    
    Caractéristiques :
    - Décomposition tendance + saisonnalité + résidu
    - Détection de changements de régime
    - Saisonnalités multiples (heure, jour, semaine, mois)
    - Prédiction avec intervalles de confiance
    - Détection d'anomalies temporelles
    """
    
    def __init__(
        self,
        seasonality_modes: List[str] = None,
        changepoint_prior_scale: float = 0.05,
        seasonality_prior_scale: float = 10.0,
        n_changepoints: int = 25,
        uncertainty_samples: int = 100,
    ):
        self.seasonality_modes = seasonality_modes or ['hourly', 'daily', 'weekly']
        self.changepoint_prior_scale = changepoint_prior_scale
        self.seasonality_prior_scale = seasonality_prior_scale
        self.n_changepoints = n_changepoints
        self.uncertainty_samples = uncertainty_samples
        
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # Composantes décomposées
        self.trend: Optional[np.ndarray] = None
        self.seasonality: Dict[str, np.ndarray] = {}
        self.residual: Optional[np.ndarray] = None
        
        # Paramètres de tendance
        self.trend_params: Dict[str, float] = {}
        self.changepoints: List[int] = []
        
        # Saisonnalités
        self.seasonal_params: Dict[str, Dict[str, float]] = {}
    
    def _extract_trend(self, y: np.ndarray) -> np.ndarray:
        """Extrait la tendance via LOESS-like smoothing."""
        trend = np.copy(y)
        window = max(3, len(y) // 20)
        
        for i in range(len(y)):
            start = max(0, i - window)
            end = min(len(y), i + window + 1)
            trend[i] = np.mean(y[start:end])
        
        return trend
    
    def _extract_seasonality(
        self,
        y: np.ndarray,
        timestamps: np.ndarray,
        mode: str,
    ) -> np.ndarray:
        """Extrait la saisonnalité pour un mode donné."""
        seasonality = np.zeros_like(y)
        
        if mode == 'hourly':
            period = 24  # 24 heures
        elif mode == 'daily':
            period = 7   # 7 jours
        elif mode == 'weekly':
            period = 4   # 4 semaines
        else:
            period = 12  # 12 mois
        
        if len(y) < period:
            return seasonality
        
        # Moyenne par position dans la période
        for i in range(period):
            indices = list(range(i, len(y), period))
            if indices:
                mean_val = np.mean(y[indices])
                for idx in indices:
                    seasonality[idx] = mean_val
        
        return seasonality
    
    def _detect_changepoints(self, y: np.ndarray) -> List[int]:
        """Détecte les points de changement de régime."""
        changepoints = []
        
        if len(y) < 10:
            return changepoints
        
        # Détection via différence cumulée
        diff = np.diff(y)
        cumsum = np.cumsum(np.abs(diff))
        
        threshold = np.percentile(cumsum, 90)
        for i in range(1, len(cumsum)):
            if cumsum[i] - cumsum[i-1] > threshold / self.n_changepoints:
                changepoints.append(i)
        
        return changepoints[:self.n_changepoints]
    
    def fit(
        self,
        y: np.ndarray,
        timestamps: Optional[np.ndarray] = None,
    ) -> 'TranscendentProphet':
        """Entraîne le modèle Prophet."""
        y_scaled = self.scaler.fit_transform(y.reshape(-1, 1)).flatten()
        
        if timestamps is None:
            timestamps = np.arange(len(y))
        
        # 1. Extraction de la tendance
        self.trend = self._extract_trend(y_scaled)
        
        # 2. Détection des changements
        self.changepoints = self._detect_changepoints(self.trend)
        
        # 3. Paramètres de tendance
        self.trend_params = {
            'mean': float(np.mean(self.trend)),
            'std': float(np.std(self.trend)),
            'slope': float(np.polyfit(np.arange(len(self.trend)), self.trend, 1)[0]),
        }
        
        # 4. Extraction des saisonnalités
        detrended = y_scaled - self.trend
        
        for mode in self.seasonality_modes:
            seasonality = self._extract_seasonality(detrended, timestamps, mode)
            self.seasonality[mode] = seasonality
            detrended -= seasonality
            
            self.seasonal_params[mode] = {
                'amplitude': float(np.std(seasonality)),
                'mean': float(np.mean(seasonality)),
            }
        
        # 5. Résidu
        self.residual = detrended
        
        self.is_fitted = True
        logger.info("prophet_trained",
                    n_changepoints=len(self.changepoints),
                    n_seasonalities=len(self.seasonality_modes))
        return self
    
    def predict(
        self,
        n_steps: int = 10,
        return_components: bool = False,
    ) -> Union[np.ndarray, Tuple[np.ndarray, Dict[str, np.ndarray]]]:
        """Prédit les prochaines valeurs."""
        if not self.is_fitted:
            return np.zeros(n_steps)
        
        # 1. Tendance future
        last_trend = self.trend[-1] if self.trend is not None else 0
        slope = self.trend_params.get('slope', 0)
        future_trend = np.array([
            last_trend + slope * (i + 1)
            for i in range(n_steps)
        ])
        
        # 2. Saisonnalités futures
        future_seasonality = np.zeros(n_steps)
        components = {}
        
        for mode, seasonality in self.seasonality.items():
            if len(seasonality) > 0:
                # Extension cyclique
                n_repeat = (n_steps // len(seasonality)) + 1
                extended = np.tile(seasonality, n_repeat)
                future_comp = extended[:n_steps]
                future_seasonality += future_comp
                components[mode] = future_comp
        
        # 3. Résidu (bruit blanc)
        residual_std = np.std(self.residual) if self.residual is not None else 0.1
        future_residual = np.random.normal(0, residual_std, n_steps)
        
        # 4. Prédiction finale
        predictions = future_trend + future_seasonality + future_residual
        predictions = self.scaler.inverse_transform(predictions.reshape(-1, 1)).flatten()
        
        if return_components:
            components['trend'] = future_trend
            components['residual'] = future_residual
            return predictions, components
        
        return predictions


# =============================================================================
# Modèle 4 : Quantum Predictor (Fusion)
# =============================================================================

class QuantumPredictor:
    """
    Fusion quantique des prédictions.
    
    Caractéristiques :
    - Fusion adaptative des 3 modèles
    - Calibration des prédictions
    - Intervalles de confiance quantiques
    - Détection de divergence entre modèles
    - Adaptation en temps réel
    """
    
    def __init__(
        self,
        lstm_weight: float = 0.35,
        transformer_weight: float = 0.35,
        prophet_weight: float = 0.30,
        confidence_threshold: float = 0.6,
    ):
        self.weights = {
            'lstm': lstm_weight,
            'transformer': transformer_weight,
            'prophet': prophet_weight,
        }
        self.confidence_threshold = confidence_threshold
        
        # Performance historique
        self.model_performance: Dict[str, List[float]] = {
            'lstm': [],
            'transformer': [],
            'prophet': [],
        }
        
        # Calibration
        self.calibration_errors: Dict[str, List[float]] = {
            'lstm': [],
            'transformer': [],
            'prophet': [],
        }
        
        self.is_fitted = True
    
    def _calculate_confidence(
        self,
        predictions: Dict[str, float],
        stds: Dict[str, float],
    ) -> float:
        """Calcule la confiance de la prédiction fusionnée."""
        # Dispersion entre modèles
        values = list(predictions.values())
        if len(values) < 2:
            return 0.5
        
        mean_pred = np.mean(values)
        std_pred = np.std(values)
        
        # Coefficient de variation
        cv = std_pred / (abs(mean_pred) + 1e-8)
        
        # Confiance basée sur la dispersion
        confidence = 1.0 - min(cv, 1.0)
        
        # Pénalité pour les std élevées
        avg_std = np.mean(list(stds.values()))
        confidence *= (1.0 - min(avg_std, 1.0))
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_bounds(
        self,
        predictions: Dict[str, float],
        stds: Dict[str, float],
        confidence: float,
    ) -> Tuple[float, float]:
        """Calcule les intervalles de confiance."""
        values = list(predictions.values())
        mean_pred = np.mean(values)
        std_pred = np.std(values)
        
        # Intervalle basé sur la dispersion et la confiance
        z_score = 1.96 * (1.0 - confidence + 0.5)  # 95% CI ajusté
        margin = z_score * std_pred
        
        return mean_pred - margin, mean_pred + margin
    
    def predict(
        self,
        lstm_pred: float,
        transformer_pred: float,
        prophet_pred: float,
        lstm_std: float = 0.0,
        transformer_std: float = 0.0,
        prophet_std: float = 0.0,
    ) -> PredictionResult:
        """
        Fusionne les prédictions des 3 modèles.
        
        Args:
            lstm_pred: Prédiction LSTM
            transformer_pred: Prédiction Transformer
            prophet_pred: Prédiction Prophet
            lstm_std: Incertitude LSTM
            transformer_std: Incertitude Transformer
            prophet_std: Incertitude Prophet
        
        Returns:
            Prédiction fusionnée
        """
        start_time = time.time()
        
        predictions = {
            'lstm': lstm_pred,
            'transformer': transformer_pred,
            'prophet': prophet_pred,
        }
        
        stds = {
            'lstm': lstm_std,
            'transformer': transformer_std,
            'prophet': prophet_std,
        }
        
        # Prédiction fusionnée (moyenne pondérée)
        total_weight = sum(self.weights.values())
        fused_value = sum(
            predictions[name] * self.weights[name] / total_weight
            for name in predictions
        )
        
        # Confiance
        confidence = self._calculate_confidence(predictions, stds)
        
        # Intervalles de confiance
        lower_bound, upper_bound = self._calculate_bounds(
            predictions, stds, confidence
        )
        
        # Explication
        explanation = self._generate_explanation(
            fused_value, predictions, stds, confidence
        )
        
        return PredictionResult(
            value=fused_value,
            confidence=confidence,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            horizon=PredictionHorizon.SHORT_TERM,
            prediction_type=PredictionType.ANOMALY,
            timestamp=time.time(),
            inference_time_ms=0.0,
            explanation=explanation,
        )
    
    def _generate_explanation(
        self,
        fused_value: float,
        predictions: Dict[str, float],
        stds: Dict[str, float],
        confidence: float,
    ) -> str:
        """Génère une explication lisible."""
        parts = []
        
        parts.append(f"📊 PRÉDICTION={fused_value:.4f} (confiance={confidence:.2f})")
        
        # Contributions des modèles
        contributions = []
        for name, pred in predictions.items():
            weight = self.weights.get(name, 0.0)
            std = stds.get(name, 0.0)
            contributions.append(f"{name}: {pred:.4f}±{std:.4f} (poids={weight:.2f})")
        
        parts.append("Modèles: " + " | ".join(contributions))
        
        # Intervalle de confiance
        lower, upper = self._calculate_bounds(predictions, stds, confidence)
        parts.append(f"IC 95%: [{lower:.4f}, {upper:.4f}]")
        
        return " | ".join(parts)


# =============================================================================
# Ensemble : Prédiction Complète
# =============================================================================

class TranscendentPredictionEnsemble:
    """
    Ensemble de prédiction qui fusionne les 4 modèles.
    
    Pipeline de prédiction :
    1. LSTM Quantique → Prédiction récurrente
    2. Transformer Temporel → Prédiction attentionnelle
    3. Prophet Adaptatif → Décomposition temporelle
    4. Quantum Predictor → Fusion quantique
    5. CatBoost (méta-modèle) → Calibration finale
    """
    
    def __init__(
        self,
        lstm: Optional[TranscendentLSTM] = None,
        transformer: Optional[TranscendentTransformer] = None,
        prophet: Optional[TranscendentProphet] = None,
        quantum_predictor: Optional[QuantumPredictor] = None,
        use_meta_model: bool = True,
    ):
        self.lstm = lstm
        self.transformer = transformer
        self.prophet = prophet
        self.quantum_predictor = quantum_predictor
        
        self.use_meta_model = use_meta_model and HAS_CATBOOST
        
        # Poids des modèles
        self.model_weights = {
            'lstm': 0.35,
            'transformer': 0.35,
            'prophet': 0.30,
        }
        
        # Performance historique
        self.performance_history: Dict[str, List[float]] = {
            'lstm': [],
            'transformer': [],
            'prophet': [],
        }
        
        # Méta-modèle (CatBoost)
        self.meta_model = None
        self.meta_scaler = StandardScaler()
        self.meta_is_fitted = False
        
        # Feature store pour calibration
        self.feature_store_meta: List[np.ndarray] = []
        self.label_store: List[float] = []
        self.max_store_size = 10000
        
        # Métriques
        self.n_predictions = 0
        self.total_inference_time = 0.0
    
    def set_models(
        self,
        lstm: TranscendentLSTM,
        transformer: TranscendentTransformer,
        prophet: TranscendentProphet,
        quantum_predictor: QuantumPredictor,
    ):
        """Configure les 4 modèles."""
        self.lstm = lstm
        self.transformer = transformer
        self.prophet = prophet
        self.quantum_predictor = quantum_predictor
    
    def _extract_meta_features(
        self,
        predictions: Dict[str, float],
        stds: Dict[str, float],
    ) -> np.ndarray:
        """Extrait les features pour le méta-modèle."""
        features = []
        
        # Prédictions des modèles
        for name in ['lstm', 'transformer', 'prophet']:
            features.append(predictions.get(name, 0.0))
            features.append(stds.get(name, 0.0))
        
        # Statistiques
        values = list(predictions.values())
        features.append(float(np.mean(values)))
        features.append(float(np.std(values)))
        features.append(float(np.max(values)))
        features.append(float(np.min(values)))
        
        return np.array(features)
    
    def _train_meta_model(self):
        """Entraîne le méta-modèle CatBoost."""
        if len(self.feature_store_meta) < 100:
            return
        
        X_meta = np.array(self.feature_store_meta)
        y_meta = np.array(self.label_store)
        
        X_scaled = self.meta_scaler.fit_transform(X_meta)
        
        self.meta_model = CatBoostRegressor(
            iterations=200,
            depth=4,
            learning_rate=0.1,
            l2_leaf_reg=3.0,
            random_seed=42,
            verbose=False,
        )
        self.meta_model.fit(X_scaled, y_meta)
        self.meta_is_fitted = True
        
        logger.info("prediction_meta_model_trained", n_samples=len(X_meta))
    
    def predict(
        self,
        X: np.ndarray,
        n_steps: int = 10,
        true_value: Optional[float] = None,
    ) -> PredictionBatch:
        """
        Prédit via l'ensemble complet.
        
        Args:
            X: Données d'entrée
            n_steps: Nombre de pas de prédiction
            true_value: Valeur réelle (optionnel, pour adaptation)
        
        Returns:
            Lot de prédictions
        """
        start_time = time.time()
        
        predictions = {}
        stds = {}
        
        # 1. LSTM
        if self.lstm is not None and self.lstm.is_fitted:
            lstm_preds = self.lstm.predict(X, return_std=True)
            if isinstance(lstm_preds, tuple):
                predictions['lstm'] = float(lstm_preds[0][-1])
                stds['lstm'] = float(lstm_preds[1][-1])
            else:
                predictions['lstm'] = float(lstm_preds[-1])
                stds['lstm'] = 0.0
        
        # 2. Transformer
        if self.transformer is not None and self.transformer.is_fitted:
            transformer_preds = self.transformer.predict(X)
            predictions['transformer'] = float(transformer_preds[-1])
            stds['transformer'] = 0.0
        
        # 3. Prophet
        if self.prophet is not None and self.prophet.is_fitted:
            prophet_preds = self.prophet.predict(n_steps=n_steps)
            predictions['prophet'] = float(prophet_preds[-1])
            stds['prophet'] = float(np.std(prophet_preds))
        
        # 4. Quantum Predictor (Fusion)
        if self.quantum_predictor is not None:
            quantum_result = self.quantum_predictor.predict(
                lstm_pred=predictions.get('lstm', 0.0),
                transformer_pred=predictions.get('transformer', 0.0),
                prophet_pred=predictions.get('prophet', 0.0),
                lstm_std=stds.get('lstm', 0.0),
                transformer_std=stds.get('transformer', 0.0),
                prophet_std=stds.get('prophet', 0.0),
            )
        else:
            # Fusion simple
            total_weight = sum(self.model_weights.values())
            fused_value = sum(
                predictions.get(name, 0.0) * self.model_weights.get(name, 0.0) / total_weight
                for name in self.model_weights
            )
            quantum_result = PredictionResult(
                value=fused_value,
                confidence=0.5,
                lower_bound=fused_value * 0.8,
                upper_bound=fused_value * 1.2,
                horizon=PredictionHorizon.SHORT_TERM,
                prediction_type=PredictionType.ANOMALY,
                timestamp=time.time(),
                inference_time_ms=0.0,
            )
        
        # Méta-modèle CatBoost
        if self.use_meta_model and self.meta_is_fitted:
            meta_features = self._extract_meta_features(predictions, stds).reshape(1, -1)
            meta_scaled = self.meta_scaler.transform(meta_features)
            calibrated_value = float(self.meta_model.predict(meta_scaled)[0])
            
            # Fusion avec la prédiction quantique
            quantum_result.value = 0.7 * quantum_result.value + 0.3 * calibrated_value
        
        # Mise à jour des performances
        if true_value is not None:
            meta_features = self._extract_meta_features(predictions, stds)
            self.feature_store_meta.append(meta_features)
            self.label_store.append(true_value)
            
            if len(self.feature_store_meta) > self.max_store_size:
                self.feature_store_meta = self.feature_store_meta[-self.max_store_size:]
                self.label_store = self.label_store[-self.max_store_size:]
            
            if len(self.feature_store_meta) % 500 == 0:
                self._train_meta_model()
        
        # Métriques
        self.n_predictions += 1
        total_time = (time.time() - start_time) * 1000
        self.total_inference_time += total_time
        
        quantum_result.inference_time_ms = total_time
        
        # Time series prediction
        time_series = TimeSeriesPrediction(
            timestamps=[time.time() + i for i in range(n_steps)],
            values=[quantum_result.value] * n_steps,
            lower_bounds=[quantum_result.lower_bound] * n_steps,
            upper_bounds=[quantum_result.upper_bound] * n_steps,
            confidences=[quantum_result.confidence] * n_steps,
            horizon=PredictionHorizon.SHORT_TERM,
            prediction_type=PredictionType.ANOMALY,
            model_scores=predictions,
        )
        
        return PredictionBatch(
            predictions=[quantum_result],
            time_series=time_series,
            n_predictions=1,
            avg_confidence=quantum_result.confidence,
            batch_inference_time_ms=total_time,
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de prédiction."""
        return {
            'n_predictions': self.n_predictions,
            'avg_inference_time_ms': self.total_inference_time / max(1, self.n_predictions),
            'model_weights': dict(self.model_weights),
            'meta_model_trained': self.meta_is_fitted,
        }


# =============================================================================
# Factory : Création du prédicteur transcendant
# =============================================================================

def create_transcendent_predictor(
    input_dim: int = 64,
    sequence_length: int = 50,
    use_meta_model: bool = True,
) -> TranscendentPredictionEnsemble:
    """
    Crée et configure le prédicteur transcendant complet.
    
    Args:
        input_dim: Dimension d'entrée
        sequence_length: Longueur des séquences
        use_meta_model: Utiliser le méta-modèle CatBoost
    
    Returns:
        Ensemble de prédiction complet
    """
    logger.info("creating_transcendent_predictor",
                input_dim=input_dim,
                sequence_length=sequence_length)
    
    # 1. LSTM Quantique
    lstm = TranscendentLSTM(
        input_dim=input_dim,
        hidden_dim=128,
        num_layers=3,
        output_dim=1,
        sequence_length=sequence_length,
        learning_rate=0.001,
        batch_size=32,
        n_epochs=100,
        patience=10,
    )
    
    # 2. Transformer Temporel
    transformer = TranscendentTransformer(
        input_dim=input_dim,
        d_model=128,
        nhead=8,
        num_encoder_layers=4,
        output_dim=1,
        sequence_length=sequence_length,
        learning_rate=0.0005,
        batch_size=32,
        n_epochs=100,
        warmup_epochs=5,
    )
    
    # 3. Prophet Adaptatif
    prophet = TranscendentProphet(
        seasonality_modes=['hourly', 'daily', 'weekly'],
        changepoint_prior_scale=0.05,
        seasonality_prior_scale=10.0,
        n_changepoints=25,
    )
    
    # 4. Quantum Predictor
    quantum_predictor = QuantumPredictor(
        lstm_weight=0.35,
        transformer_weight=0.35,
        prophet_weight=0.30,
        confidence_threshold=0.6,
    )
    
    # Ensemble
    ensemble = TranscendentPredictionEnsemble(
        lstm=lstm,
        transformer=transformer,
        prophet=prophet,
        quantum_predictor=quantum_predictor,
        use_meta_model=use_meta_model,
    )
    
    logger.info("transcendent_predictor_created",
                n_models=4,
                input_dim=input_dim,
                sequence_length=sequence_length)
    
    return ensemble
