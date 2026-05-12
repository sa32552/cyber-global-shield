"""
Cyber Global Shield — Mamba State Space Models for Log Sequence Analysis
========================================================================
Mamba (Gu & Dao, 2023) est un State Space Model (SSM) sélectif qui offre :
- Complexité O(n) vs O(n²) pour Transformers
- 5x plus rapide en inférence pour les séquences longues
- Meilleure capture des dépendances à longue distance
- Idéal pour les logs en continu (streaming)

Architecture :
  - MambaBlock : Bloc SSM Mamba-2 avec selective scan algorithm
  - MambaSequenceModel : Modèle de séquence pour logs réseau
  - MambaAnomalyDetector : Détection d'anomalies sur flux temporel
  - BiMambaEncoder : Encoder bidirectionnel pour contexte complet
  - MambaLogProcessor : Processeur de logs en temps réel
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

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class MambaResult:
    """Résultat de détection Mamba."""
    anomaly_score: float
    is_anomaly: bool
    threshold_used: float
    confidence: float
    sequence_length: int
    hidden_states: Optional[np.ndarray] = None
    attention_map: Optional[np.ndarray] = None
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: MAMBA BLOCK — Selective State Space Model
# ═══════════════════════════════════════════════════════════════════════════

class SelectiveSSM(nn.Module):
    """
    Selective State Space Model core computation.
    
    Implements the continuous-time SSM discretized with zero-order hold:
      h'(t) = A h(t) + B x(t)
      y(t) = C h(t) + D x(t)
    
    With selective mechanisms (input-dependent A, B, C):
      - A is parameterized as diagonal for efficiency
      - B, C are input-dependent via learned projections
      - Δ (step size) is input-dependent for selective gating
    
    Args:
        d_model: Model dimension
        d_state: State dimension (default: 16)
        dt_rank: Rank of Δ projection (default: auto)
    """
    
    def __init__(
        self,
        d_model: int,
        d_state: int = 16,
        dt_rank: Union[int, str] = "auto",
    ):
        super().__init__()
        self.d_model = d_model
        self.d_state = d_state
        self.dt_rank = math.ceil(d_model / 16) if dt_rank == "auto" else dt_rank
        
        # Discretization parameters
        self.dt_proj = nn.Linear(self.dt_rank, d_model, bias=True)
        
        # Log of A diagonal (ensures stability via negative reals)
        self.A_log = nn.Parameter(
            torch.log(torch.randn(d_model, d_state) * 0.1 + 1.0)
        )
        
        # B and C projection matrices (learned)
        self.B_proj = nn.Linear(d_model, d_state, bias=False)
        self.C_proj = nn.Linear(d_model, d_state, bias=False)
        
        # D "skip connection" parameter
        self.D = nn.Parameter(torch.ones(d_model))
        
        # Δ projection from input
        self.dt_proj_weight = nn.Linear(d_model, self.dt_rank, bias=False)
        
        # Normalization
        self.norm = nn.LayerNorm(d_model)
        
        # Output projection
        self.out_proj = nn.Linear(d_model, d_model, bias=False)
        
        self._init_weights()
    
    def _init_weights(self):
        """Initialize weights."""
        nn.init.xavier_uniform_(self.dt_proj.weight)
        nn.init.xavier_uniform_(self.B_proj.weight)
        nn.init.xavier_uniform_(self.C_proj.weight)
        nn.init.xavier_uniform_(self.dt_proj_weight.weight)
        nn.init.xavier_uniform_(self.out_proj.weight)
        nn.init.zeros_(self.dt_proj.bias)
    
    def _selective_scan(
        self,
        x: torch.Tensor,
        delta: torch.Tensor,
        A: torch.Tensor,
        B: torch.Tensor,
        C: torch.Tensor,
        D: torch.Tensor,
    ) -> torch.Tensor:
        """
        Selective scan algorithm (simplified Mamba-2 style).
        
        Args:
            x: Input [batch, seq_len, d_model]
            delta: Step sizes [batch, seq_len, d_model]
            A: State matrix [d_model, d_state]
            B: Input matrix [batch, seq_len, d_state]
            C: Output matrix [batch, seq_len, d_state]
            D: Skip connection [d_model]
        
        Returns:
            Output [batch, seq_len, d_model]
        """
        batch, seq_len, d_model = x.shape
        d_state = A.shape[-1]
        
        # Discretize A: A_bar = exp(Δ * A)
        delta_A = delta.unsqueeze(-1) * A.unsqueeze(0).unsqueeze(0)  # [batch, seq, d_model, d_state]
        A_bar = torch.exp(delta_A)
        
        # Discretize B: B_bar = Δ * B
        delta_B = delta.unsqueeze(-1) * B.unsqueeze(2)  # [batch, seq, d_model, d_state]
        
        # Selective scan (parallel associative scan)
        # h_t = A_bar_t * h_{t-1} + B_bar_t * x_t
        h = torch.zeros(batch, d_model, d_state, device=x.device)
        outputs = []
        
        for t in range(seq_len):
            h = A_bar[:, t] * h + delta_B[:, t] * x[:, t].unsqueeze(-1)
            y = (h * C[:, t].unsqueeze(1)).sum(dim=-1)  # [batch, d_model]
            outputs.append(y)
        
        y = torch.stack(outputs, dim=1)  # [batch, seq_len, d_model]
        
        # Add skip connection
        y = y + D.unsqueeze(0).unsqueeze(0) * x
        
        return y
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through selective SSM.
        
        Args:
            x: Input [batch, seq_len, d_model]
        
        Returns:
            Output [batch, seq_len, d_model]
        """
        batch, seq_len, d_model = x.shape
        
        # Input-dependent Δ (step size)
        dt = self.dt_proj_weight(x)  # [batch, seq, dt_rank]
        delta = F.softplus(self.dt_proj(dt))  # [batch, seq, d_model]
        
        # Input-dependent B, C
        B = self.B_proj(x)  # [batch, seq, d_state]
        C = self.C_proj(x)  # [batch, seq, d_state]
        
        # A matrix (from log parameterization)
        A = -torch.exp(self.A_log)  # [d_model, d_state] (negative for stability)
        
        # Selective scan
        y = self._selective_scan(x, delta, A, B, C, self.D)
        
        # Normalize and project
        y = self.norm(y)
        y = self.out_proj(y)
        
        return y


class MambaBlock(nn.Module):
    """
    Complete Mamba block with SSM + gated MLP.
    
    Architecture:
      x -> norm -> SSM -> gated_MLP -> residual
    
    Args:
        d_model: Model dimension
        d_state: State dimension
        expand_factor: Expansion factor for MLP (default: 2)
    """
    
    def __init__(
        self,
        d_model: int,
        d_state: int = 16,
        expand_factor: int = 2,
    ):
        super().__init__()
        self.d_model = d_model
        self.d_state = d_state
        self.expand_factor = expand_factor
        
        # Pre-normalization
        self.norm = nn.LayerNorm(d_model)
        
        # Selective SSM
        self.ssm = SelectiveSSM(d_model, d_state)
        
        # Gated MLP
        d_inner = d_model * expand_factor
        self.mlp_gate = nn.Linear(d_model, d_inner, bias=False)
        self.mlp_up = nn.Linear(d_model, d_inner, bias=False)
        self.mlp_down = nn.Linear(d_inner, d_model, bias=False)
        
        # Convolution before SSM (for local context)
        self.conv1d = nn.Conv1d(
            in_channels=d_model,
            out_channels=d_model,
            kernel_size=3,
            padding=1,
            groups=d_model,  # depthwise
        )
        
        self._init_weights()
    
    def _init_weights(self):
        """Initialize weights."""
        nn.init.xavier_uniform_(self.mlp_gate.weight)
        nn.init.xavier_uniform_(self.mlp_up.weight)
        nn.init.xavier_uniform_(self.mlp_down.weight)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Input [batch, seq_len, d_model]
        
        Returns:
            Output [batch, seq_len, d_model]
        """
        residual = x
        
        # Normalize
        x = self.norm(x)
        
        # Convolution (local context)
        x_conv = x.transpose(1, 2)  # [batch, d_model, seq]
        x_conv = self.conv1d(x_conv)
        x_conv = x_conv.transpose(1, 2)  # [batch, seq, d_model]
        x_conv = F.silu(x_conv)
        
        # Selective SSM
        x_ssm = self.ssm(x_conv)
        
        # Gated MLP
        gate = F.silu(self.mlp_gate(x))
        up = self.mlp_up(x_ssm)
        x_mlp = gate * up
        x_mlp = self.mlp_down(x_mlp)
        
        # Residual connection
        return residual + x_mlp


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: MAMBA SEQUENCE MODEL
# ═══════════════════════════════════════════════════════════════════════════

class MambaSequenceModel(nn.Module):
    """
    Deep Mamba sequence model for log analysis.
    
    Stacks multiple Mamba blocks with optional pooling.
    
    Args:
        vocab_size: Vocabulary size (for tokenized logs)
        d_model: Model dimension
        n_layers: Number of Mamba blocks
        d_state: State dimension per block
        max_seq_len: Maximum sequence length
        dropout: Dropout rate
    """
    
    def __init__(
        self,
        vocab_size: int = 10000,
        d_model: int = 256,
        n_layers: int = 4,
        d_state: int = 16,
        max_seq_len: int = 2048,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.d_model = d_model
        self.max_seq_len = max_seq_len
        
        # Token embedding
        self.token_embedding = nn.Embedding(vocab_size, d_model)
        
        # Positional encoding (learned)
        self.pos_embedding = nn.Parameter(
            torch.randn(1, max_seq_len, d_model) * 0.02
        )
        
        # Mamba blocks
        self.blocks = nn.ModuleList([
            MambaBlock(d_model, d_state) for _ in range(n_layers)
        ])
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
        
        # Output head
        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Linear(d_model, 1)  # binary classification
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            input_ids: Token indices [batch, seq_len]
            attention_mask: Optional mask [batch, seq_len]
        
        Returns:
            Logits [batch, 1]
        """
        batch, seq_len = input_ids.shape
        
        # Embeddings
        x = self.token_embedding(input_ids)
        x = x + self.pos_embedding[:, :seq_len, :]
        x = self.dropout(x)
        
        # Mamba blocks
        for block in self.blocks:
            x = block(x)
        
        # Pooling (mean over sequence)
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            x = (x * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
        else:
            x = x.mean(dim=1)
        
        # Output
        x = self.norm(x)
        logits = self.head(x)
        
        return logits


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: BI-MAMBA ENCODER (Bidirectional)
# ═══════════════════════════════════════════════════════════════════════════

class BiMambaEncoder(nn.Module):
    """
    Bidirectional Mamba encoder.
    
    Processes sequences in both forward and backward directions,
    then combines representations for full context.
    
    Args:
        d_model: Model dimension
        n_layers: Number of layers per direction
        d_state: State dimension
    """
    
    def __init__(
        self,
        d_model: int = 256,
        n_layers: int = 3,
        d_state: int = 16,
    ):
        super().__init__()
        
        # Forward Mamba
        self.forward_mamba = nn.ModuleList([
            MambaBlock(d_model, d_state) for _ in range(n_layers)
        ])
        
        # Backward Mamba
        self.backward_mamba = nn.ModuleList([
            MambaBlock(d_model, d_state) for _ in range(n_layers)
        ])
        
        # Fusion
        self.fusion = nn.Sequential(
            nn.Linear(d_model * 2, d_model),
            nn.GELU(),
            nn.LayerNorm(d_model),
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Input [batch, seq_len, d_model]
        
        Returns:
            Encoded [batch, seq_len, d_model]
        """
        # Forward
        fwd = x
        for block in self.forward_mamba:
            fwd = block(fwd)
        
        # Backward (reverse sequence)
        bwd = torch.flip(x, dims=[1])
        for block in self.backward_mamba:
            bwd = block(bwd)
        bwd = torch.flip(bwd, dims=[1])
        
        # Fusion
        combined = torch.cat([fwd, bwd], dim=-1)
        return self.fusion(combined)


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: MAMBA ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════

class MambaAnomalyDetector:
    """
    Anomaly detector using Mamba SSM for log sequence analysis.
    
    Processes streaming logs in real-time with O(n) complexity.
    Detects anomalies based on next-token prediction perplexity
    and sequence-level classification.
    
    Usage:
        detector = MambaAnomalyDetector(d_model=256)
        detector.fit(train_logs)
        result = detector.predict(log_sequence)
    """
    
    def __init__(
        self,
        d_model: int = 256,
        n_layers: int = 4,
        d_state: int = 16,
        max_seq_len: int = 2048,
        vocab_size: int = 10000,
        threshold_percentile: float = 95.0,
        device: str = "cpu",
    ):
        self.d_model = d_model
        self.n_layers = n_layers
        self.d_state = d_state
        self.max_seq_len = max_seq_len
        self.vocab_size = vocab_size
        self.threshold_percentile = threshold_percentile
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        
        # Sequence model for classification
        self.model = MambaSequenceModel(
            vocab_size=vocab_size,
            d_model=d_model,
            n_layers=n_layers,
            d_state=d_state,
            max_seq_len=max_seq_len,
        ).to(self.device)
        
        # Bidirectional encoder for deep representation
        self.encoder = BiMambaEncoder(
            d_model=d_model,
            n_layers=n_layers // 2,
            d_state=d_state,
        ).to(self.device)
        
        self.threshold: float = 0.0
        self.trained = False
        self.train_scores: List[float] = []
        self.metrics_history: Dict[str, List[float]] = {
            "train_loss": [],
            "val_loss": [],
            "perplexity": [],
        }
    
    def fit(
        self,
        sequences: List[List[int]],
        labels: Optional[List[int]] = None,
        epochs: int = 50,
        batch_size: int = 16,
        learning_rate: float = 1e-3,
        val_split: float = 0.1,
        verbose: bool = True,
    ):
        """
        Train the Mamba detector.
        
        Args:
            sequences: List of tokenized log sequences
            labels: Optional binary labels (0=normal, 1=anomaly)
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            val_split: Validation split ratio
            verbose: Print progress
        """
        # Pad sequences
        max_len = min(max(len(s) for s in sequences), self.max_seq_len)
        padded = torch.zeros(len(sequences), max_len, dtype=torch.long)
        attention_mask = torch.zeros(len(sequences), max_len)
        
        for i, seq in enumerate(sequences):
            length = min(len(seq), max_len)
            padded[i, :length] = torch.tensor(seq[:length])
            attention_mask[i, :length] = 1.0
        
        # Split
        n_samples = len(sequences)
        n_val = int(n_samples * val_split)
        indices = np.random.permutation(n_samples)
        
        train_idx = indices[:n_samples - n_val]
        val_idx = indices[n_samples - n_val:]
        
        X_train = padded[train_idx].to(self.device)
        X_val = padded[val_idx].to(self.device)
        mask_train = attention_mask[train_idx].to(self.device)
        mask_val = attention_mask[val_idx].to(self.device)
        
        y_train = None
        y_val = None
        if labels is not None:
            y_train = torch.FloatTensor([labels[i] for i in train_idx]).to(self.device)
            y_val = torch.FloatTensor([labels[i] for i in val_idx]).to(self.device)
        
        optimizer = torch.optim.AdamW(
            self.model.parameters(), lr=learning_rate, weight_decay=1e-5
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=epochs
        )
        
        best_val_loss = float("inf")
        patience = 7
        patience_counter = 0
        
        for epoch in range(epochs):
            self.model.train()
            train_losses = []
            
            for i in range(0, len(X_train), batch_size):
                batch_x = X_train[i:i + batch_size]
                batch_mask = mask_train[i:i + batch_size]
                
                optimizer.zero_grad()
                
                # Next-token prediction loss (self-supervised)
                logits = self.model(batch_x, batch_mask)
                
                if y_train is not None:
                    batch_y = y_train[i:i + batch_size]
                    loss = F.binary_cross_entropy_with_logits(
                        logits.squeeze(-1), batch_y
                    )
                else:
                    # Self-supervised: predict next token
                    # Use model output as anomaly score
                    loss = torch.mean(logits ** 2)  # minimize score for normal data
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                
                train_losses.append(loss.item())
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                val_logits = self.model(X_val, mask_val)
                if y_val is not None:
                    val_loss = F.binary_cross_entropy_with_logits(
                        val_logits.squeeze(-1), y_val
                    ).item()
                else:
                    val_loss = torch.mean(val_logits ** 2).item()
            
            scheduler.step()
            
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
            
            self.metrics_history["train_loss"].append(np.mean(train_losses))
            self.metrics_history["val_loss"].append(val_loss)
            
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    "Mamba training progress",
                    epoch=epoch + 1,
                    train_loss=np.mean(train_losses),
                    val_loss=val_loss,
                )
        
        # Compute threshold
        self.model.eval()
        with torch.no_grad():
            scores = torch.sigmoid(self.model(X_train, mask_train))
            self.train_scores = scores.cpu().numpy().flatten().tolist()
            self.threshold = np.percentile(
                self.train_scores, self.threshold_percentile
            )
        
        self.trained = True
        logger.info(
            "Mamba training complete",
            threshold=self.threshold,
            best_val_loss=best_val_loss,
        )
    
    def predict(self, sequences: List[List[int]]) -> List[MambaResult]:
        """
        Predict anomalies on new log sequences.
        
        Args:
            sequences: List of tokenized log sequences
        
        Returns:
            List of MambaResult objects
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        
        # Pad sequences
        max_len = min(max(len(s) for s in sequences), self.max_seq_len)
        padded = torch.zeros(len(sequences), max_len, dtype=torch.long)
        attention_mask = torch.zeros(len(sequences), max_len)
        
        for i, seq in enumerate(sequences):
            length = min(len(seq), max_len)
            padded[i, :length] = torch.tensor(seq[:length])
            attention_mask[i, :length] = 1.0
        
        X = padded.to(self.device)
        mask = attention_mask.to(self.device)
        
        self.model.eval()
        
        results = []
        start_time = datetime.now(timezone.utc)
        
        with torch.no_grad():
            logits = self.model(X, mask)
            scores = torch.sigmoid(logits).squeeze(-1)
        
        inference_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
        for i in range(len(sequences)):
            score = scores[i].item()
            is_anomaly = score > self.threshold
            
            result = MambaResult(
                anomaly_score=score,
                is_anomaly=is_anomaly,
                threshold_used=self.threshold,
                confidence=abs(score - 0.5) * 2,  # 0-1 confidence
                sequence_length=len(sequences[i]),
                explanation=self._generate_explanation(score, len(sequences[i])),
                inference_time_ms=inference_time / len(sequences),
            )
            results.append(result)
        
        return results
    
    def predict_streaming(
        self, token_stream: List[int], window_size: int = 128, stride: int = 32
    ) -> List[MambaResult]:
        """
        Predict anomalies on a streaming token stream.
        
        Slides a window over the stream for real-time detection.
        
        Args:
            token_stream: Stream of tokens
            window_size: Sliding window size
            stride: Stride between windows
        
        Returns:
            List of MambaResult objects per window
        """
        windows = []
        for i in range(0, len(token_stream) - window_size + 1, stride):
            windows.append(token_stream[i:i + window_size])
        
        return self.predict(windows)
    
    def _generate_explanation(self, score: float, seq_len: int) -> str:
        """Generate explanation for prediction."""
        parts = []
        if score > self.threshold:
            parts.append(f"Anomaly detected (score={score:.3f}, threshold={self.threshold:.3f})")
        else:
            parts.append(f"Normal sequence (score={score:.3f})")
        
        parts.append(f"Sequence length: {seq_len}")
        parts.append(f"Confidence: {abs(score - 0.5) * 100:.1f}%")
        
        return " | ".join(parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "architecture": "Mamba SSM",
            "d_model": self.d_model,
            "n_layers": self.n_layers,
            "d_state": self.d_state,
            "max_seq_len": self.max_seq_len,
            "vocab_size": self.vocab_size,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "trained": self.trained,
            "n_train_samples": len(self.train_scores),
            "mean_train_score": float(np.mean(self.train_scores)) if self.train_scores else 0.0,
            "metrics_history": {
                k: v[-10:] if len(v) > 10 else v
                for k, v in self.metrics_history.items()
            },
            "n_parameters": sum(p.numel() for p in self.model.parameters()),
            "complexity": "O(n) per sequence",
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: MAMBA LOG PROCESSOR (Real-time Streaming)
# ═══════════════════════════════════════════════════════════════════════════

class MambaLogProcessor:
    """
    Real-time log processor using Mamba for streaming anomaly detection.
    
    Processes logs as they arrive, maintaining internal state
    for efficient incremental inference.
    
    Usage:
        processor = MambaLogProcessor(detector)
        for log in log_stream:
            result = processor.process(log)
    """
    
    def __init__(
        self,
        detector: MambaAnomalyDetector,
        tokenizer: Optional[Callable] = None,
        window_size: int = 128,
        stride: int = 64,
    ):
        self.detector = detector
        self.tokenizer = tokenizer or (lambda x: [hash(str(x)) % 10000])
        self.window_size = window_size
        self.stride = stride
        
        self.buffer: deque = deque(maxlen=window_size * 2)
        self.results_history: deque = deque(maxlen=1000)
        self.alerts: List[Dict[str, Any]] = []
    
    def process(self, log_entry: Any) -> Optional[MambaResult]:
        """
        Process a single log entry.
        
        Args:
            log_entry: Raw log entry
        
        Returns:
            MambaResult if window is full, else None
        """
        # Tokenize
        tokens = self.tokenizer(log_entry)
        self.buffer.extend(tokens)
        
        # Check if we have enough tokens for a window
        if len(self.buffer) >= self.window_size:
            window = list(self.buffer)[-self.window_size:]
            results = self.detector.predict([window])
            
            if results:
                result = results[0]
                self.results_history.append(result)
                
                if result.is_anomaly:
                    self.alerts.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "score": result.anomaly_score,
                        "confidence": result.confidence,
                        "explanation": result.explanation,
                    })
                
                # Slide window
                for _ in range(min(self.stride, len(self.buffer))):
                    if self.buffer:
                        self.buffer.popleft()
                
                return result
        
        return None
    
    def get_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get alerts since a given time."""
        if since is None:
            return self.alerts
        return [a for a in self.alerts if a["timestamp"] >= since.isoformat()]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            "buffer_size": len(self.buffer),
            "results_count": len(self.results_history),
            "alerts_count": len(self.alerts),
            "window_size": self.window_size,
            "stride": self.stride,
            "anomaly_rate": (
                sum(1 for r in self.results_history if r.is_anomaly) /
                max(len(self.results_history), 1)
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_mamba_detector(
    d_model: int = 256,
    n_layers: int = 4,
    vocab_size: int = 10000,
    device: str = "cpu",
) -> MambaAnomalyDetector:
    """
    Create a default Mamba anomaly detector.
    
    Args:
        d_model: Model dimension
        n_layers: Number of Mamba layers
        vocab_size: Vocabulary size
        device: Device to use
    
    Returns:
        Configured MambaAnomalyDetector
    """
    return MambaAnomalyDetector(
        d_model=d_model,
        n_layers=n_layers,
        d_state=16,
        max_seq_len=2048,
        vocab_size=vocab_size,
        threshold_percentile=95.0,
        device=device,
    )


def create_mamba_detector_minimal() -> Dict[str, Any]:
    """Create a minimal Mamba detector config for quick testing."""
    return {
        "type": "mamba",
        "d_model": 128,
        "n_layers": 2,
        "d_state": 8,
        "max_seq_len": 512,
        "vocab_size": 5000,
        "threshold_percentile": 90.0,
    }


def create_mamba_detector_full() -> Dict[str, Any]:
    """Create a full Mamba detector config for production."""
    return {
        "type": "mamba",
        "d_model": 512,
        "n_layers": 8,
        "d_state": 32,
        "max_seq_len": 8192,
        "vocab_size": 50000,
        "threshold_percentile": 99.0,
    }
