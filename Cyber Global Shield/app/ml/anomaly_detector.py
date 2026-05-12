import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AnomalyDetectionResult:
    anomaly_score: float
    reconstruction_error: float
    is_anomaly: bool
    threshold_used: float
    feature_scores: Optional[Dict[str, float]] = None
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0


class TransformerAutoencoder(nn.Module):
    """
    Transformer-based autoencoder for network traffic anomaly detection.
    Uses self-attention to capture long-range dependencies in log sequences.
    """

    def __init__(
        self,
        input_dim: int = 128,
        d_model: int = 256,
        nhead: int = 8,
        num_encoder_layers: int = 4,
        num_decoder_layers: int = 2,
        dim_feedforward: int = 1024,
        dropout: float = 0.1,
        latent_dim: int = 64,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        self.latent_dim = latent_dim

        # Input projection
        self.input_proj = nn.Linear(input_dim, d_model)
        self.pos_encoding = PositionalEncoding(d_model, dropout)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_encoder_layers)

        # Bottleneck
        self.encoder_to_latent = nn.Sequential(
            nn.Linear(d_model, latent_dim * 2),
            nn.GELU(),
            nn.Linear(latent_dim * 2, latent_dim),
        )
        self.latent_to_decoder = nn.Sequential(
            nn.Linear(latent_dim, latent_dim * 2),
            nn.GELU(),
            nn.Linear(latent_dim * 2, d_model),
        )

        # Transformer decoder
        decoder_layer = nn.TransformerDecoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.decoder = nn.TransformerDecoder(decoder_layer, num_layers=num_decoder_layers)

        # Output projection
        self.output_proj = nn.Linear(d_model, input_dim)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        # x: (batch_size, seq_len, input_dim)
        batch_size, seq_len, _ = x.shape

        # Project input
        x = self.input_proj(x)
        x = self.pos_encoding(x)

        # Encode
        memory = self.encoder(x)

        # Compress to latent
        latent = self.encoder_to_latent(memory.mean(dim=1))  # Global pooling

        # Expand back
        expanded = self.latent_to_decoder(latent).unsqueeze(1).repeat(1, seq_len, 1)

        # Decode
        decoded = self.decoder(expanded, memory)

        # Project to input space
        reconstructed = self.output_proj(decoded)

        return reconstructed, latent


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, dropout: float = 0.1, max_len: int = 5000):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2) * (-np.log(10000.0) / d_model)
        )
        pe = torch.zeros(max_len, 1, d_model)
        pe[:, 0, 0::2] = torch.sin(position * div_term)
        pe[:, 0, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, d_model)
        x = x.transpose(0, 1)  # (seq_len, batch, d_model)
        x = x + self.pe[: x.size(0)]
        return self.dropout(x).transpose(0, 1)  # (batch, seq_len, d_model)


class IsolationForestWrapper:
    """Lightweight Isolation Forest for real-time quick screening."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, X: np.ndarray):
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._fitted = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        # Normalize to 0-1 (higher = more anomalous)
        anomaly_scores = 1.0 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return anomaly_scores


class FeatureIndices:
    """Named constants for feature vector indices to avoid magic numbers."""
    SRC_IP = 0
    DST_IP = 1
    SRC_PORT = 2
    DST_PORT = 3
    PROTOCOL = 4
    EVENT_TYPE_START = 5
    EVENT_TYPE_END = 16  # 12 event types (5 to 16 inclusive)
    SEVERITY = 17
    HOUR = 18
    MINUTE = 19
    WEEKDAY = 20
    BYTES_SENT = 21
    BYTES_RECEIVED = 22
    PACKETS_SENT = 23
    PACKETS_RECEIVED = 24
    HTTP_METHOD = 25
    HTTP_RESPONSE_CODE = 26
    HTTP_URL_HASH = 27
    FILE_HASH = 28
    DNS_QUERY_LENGTH = 29
    USER_AGENT_HASH = 30
    PROCESS_ID = 31
    TAGS_START = 32
    TAGS_END = 36  # 5 tags (32 to 36 inclusive)
    FEATURE_DIM = 128


class AnomalyDetector:
    """
    Main anomaly detector combining Transformer Autoencoder + Isolation Forest.
    Two-stage detection: fast screening with IF, then deep analysis with autoencoder.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: str = "cpu",
        use_isolation_forest: bool = True,
    ):
        self.device = torch.device(device)
        self.model = TransformerAutoencoder()
        self.model.to(self.device)
        self.model.eval()

        self.isolation_forest = None
        if use_isolation_forest:
            self.isolation_forest = IsolationForestWrapper()

        self.threshold = 0.95  # Will be calibrated
        self._thresholds_per_feature: Dict[int, float] = {}
        self.feature_names: List[str] = []

        if model_path:
            self.load(model_path)

    def load(self, path: str):
        """Load model weights."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        if "threshold" in checkpoint:
            self.threshold = checkpoint["threshold"]
        if "isolation_forest" in checkpoint and checkpoint["isolation_forest"]:
            self.isolation_forest = checkpoint["isolation_forest"]
        logger.info("model_loaded", path=path)

    def save(self, path: str):
        """Save model weights."""
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "threshold": self.threshold,
                "isolation_forest": self.isolation_forest,
            },
            path,
        )
        logger.info("model_saved", path=path)

    def preprocess(
        self, logs: List[Dict[str, Any]], seq_len: int = 64
    ) -> torch.Tensor:
        """Convert raw logs to model input tensor."""
        features_list = []

        for log in logs:
            feat = self._log_to_features(log)
            features_list.append(feat)

        if not features_list:
            return torch.zeros(1, seq_len, 128)

        # Handle variable length by padding/truncating
        if len(features_list) < seq_len:
            # Pad with zeros
            padding = np.zeros((seq_len - len(features_list), 128))
            features_list = np.vstack([features_list, padding])
        else:
            features_list = np.array(features_list[-seq_len:])

        # Ensure shape
        if len(features_list.shape) == 1:
            features_list = features_list.reshape(1, -1)

        # Take last seq_len
        features_list = features_list[:seq_len]

        # Add batch dimension
        tensor = torch.FloatTensor(features_list).unsqueeze(0)
        return tensor

    def _log_to_features(self, log: Dict[str, Any]) -> np.ndarray:
        """Convert a single log to feature vector using FeatureIndices constants."""
        features = np.zeros(FeatureIndices.FEATURE_DIM)

        # IP encoding (simple hash-based)
        src_ip = log.get("src_ip", "")
        dst_ip = log.get("dst_ip", "")
        if src_ip:
            features[FeatureIndices.SRC_IP] = hash(src_ip) % 1000 / 1000.0
        if dst_ip:
            features[FeatureIndices.DST_IP] = hash(dst_ip) % 1000 / 1000.0

        # Ports (normalized)
        features[FeatureIndices.SRC_PORT] = min(log.get("src_port", 0) or 0, 65535) / 65535.0
        features[FeatureIndices.DST_PORT] = min(log.get("dst_port", 0) or 0, 65535) / 65535.0

        # Protocol encoding
        protocol_map = {
            "tcp": 0.1, "udp": 0.2, "icmp": 0.3, "http": 0.4, "https": 0.5,
            "dns": 0.6, "ssh": 0.7, "ftp": 0.8, "smtp": 0.9, "smb": 1.0
        }
        features[FeatureIndices.PROTOCOL] = protocol_map.get(log.get("protocol", "").lower(), 0.0)

        # Event type encoding (one-hot over 12 types)
        event_types = [
            "scan", "auth_failure", "brute_force", "malware_detected",
            "c2_communication", "data_exfiltration", "lateral_movement",
            "privilege_escalation", "ransomware_activity", "http_request", "dns_query", "file_access"
        ]
        event_type = log.get("event_type", "").lower()
        if event_type in event_types:
            idx = event_types.index(event_type)
            features[FeatureIndices.EVENT_TYPE_START + idx] = 1.0

        # Severity encoding
        severity_map = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.7, "critical": 1.0}
        features[FeatureIndices.SEVERITY] = severity_map.get(log.get("severity", "info"), 0.0)

        # Time features
        from datetime import datetime, timezone
        try:
            ts = log.get("timestamp", datetime.now(timezone.utc))
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            features[FeatureIndices.HOUR] = ts.hour / 24.0
            features[FeatureIndices.MINUTE] = ts.minute / 60.0
            features[FeatureIndices.WEEKDAY] = ts.weekday() / 7.0
        except Exception:
            pass

        # Bytes/packets if available
        features[FeatureIndices.BYTES_SENT] = min(log.get("bytes_sent", 0) or 0, 1_000_000) / 1_000_000.0
        features[FeatureIndices.BYTES_RECEIVED] = min(log.get("bytes_received", 0) or 0, 1_000_000) / 1_000_000.0
        features[FeatureIndices.PACKETS_SENT] = min(log.get("packets_sent", 0) or 0, 10000) / 10000.0
        features[FeatureIndices.PACKETS_RECEIVED] = min(log.get("packets_received", 0) or 0, 10000) / 10000.0

        # HTTP specific features
        if log.get("event_type") == "http_request":
            http_method_map = {"get": 0.1, "post": 0.2, "put": 0.3, "delete": 0.4}
            features[FeatureIndices.HTTP_METHOD] = http_method_map.get(log.get("http_method", "").lower(), 0.0)
            features[FeatureIndices.HTTP_RESPONSE_CODE] = min(log.get("response_code", 0) or 0, 599) / 599.0
            if log.get("url"):
                features[FeatureIndices.HTTP_URL_HASH] = hash(log["url"]) % 1000 / 1000.0

        # File hash features
        if log.get("file_hash"):
            features[FeatureIndices.FILE_HASH] = hash(log["file_hash"]) % 1000 / 1000.0

        # DNS query length
        if log.get("event_type") == "dns_query" and log.get("query_length"):
            features[FeatureIndices.DNS_QUERY_LENGTH] = min(log["query_length"], 255) / 255.0

        # User agent (simple hash)
        if log.get("user_agent"):
            features[FeatureIndices.USER_AGENT_HASH] = hash(log["user_agent"]) % 1000 / 1000.0

        # Process ID
        if log.get("process_id"):
            features[FeatureIndices.PROCESS_ID] = min(log["process_id"], 65535) / 65535.0

        # Tags (encode presence of specific tags)
        if log.get("tags"):
            tag_names = ["malicious", "c2", "exploit", "phishing", "ransomware"]
            for tag in tag_names:
                if tag in log["tags"]:
                    features[FeatureIndices.TAGS_START + tag_names.index(tag)] = 1.0

        return features

    def detect(
        self,
        logs: List[Dict[str, Any]],
        threshold: Optional[float] = None,
    ) -> AnomalyDetectionResult:
        """Detect anomalies in a sequence of logs."""
        import time
        start_time = time.time()

        if threshold is None:
            threshold = self.threshold

        # Stage 1: Quick Isolation Forest screening
        if self.isolation_forest and self.isolation_forest._fitted and len(logs) == 1:
            features = self._log_to_features(logs[0]).reshape(1, -1)
            if_score = self.isolation_forest.predict(features)[0]
            if if_score < 0.5:  # Clearly normal
                return AnomalyDetectionResult(
                    anomaly_score=if_score,
                    reconstruction_error=0.0,
                    is_anomaly=False,
                    threshold_used=threshold,
                    inference_time_ms=(time.time() - start_time) * 1000,
                )

        # Stage 2: Deep Transformer Autoencoder analysis
        with torch.no_grad():
            x = self.preprocess(logs).to(self.device)
            reconstructed, latent = self.model(x)

            # Per-feature reconstruction error
            errors = F.mse_loss(reconstructed, x, reduction="none")
            feature_errors = errors.mean(dim=(0, 1)).cpu().numpy()

            # Overall reconstruction error
            total_error = errors.mean().item()

            # Anomaly score based on reconstruction error
            anomaly_score = self._compute_anomaly_score(total_error, feature_errors)

            is_anomaly = anomaly_score > threshold

            # Explanation
            explanation = self._generate_explanation(
                feature_errors, x[0, -1].cpu().numpy(), reconstructed[0, -1].cpu().numpy()
            ) if is_anomaly else None

            feature_scores = {}
            if self.feature_names:
                for i, name in enumerate(self.feature_names[:len(feature_errors)]):
                    feature_scores[name] = float(feature_errors[i])

        inference_time = (time.time() - start_time) * 1000

        return AnomalyDetectionResult(
            anomaly_score=float(anomaly_score),
            reconstruction_error=float(total_error),
            is_anomaly=is_anomaly,
            threshold_used=threshold,
            feature_scores=feature_scores if feature_scores else None,
            explanation=explanation,
            inference_time_ms=inference_time,
        )

    def _compute_anomaly_score(
        self, total_error: float, feature_errors: np.ndarray
    ) -> float:
        """Compute normalized anomaly score from reconstruction error."""
        max_err = feature_errors.max() if len(feature_errors) > 0 else total_error
        normalized = min(total_error / (max_err + 1e-8), 10.0)
        score = 1.0 - np.exp(-normalized)
        return float(np.clip(score, 0.0, 1.0))

    def _generate_explanation(
        self, feature_errors: np.ndarray, original: np.ndarray, reconstructed: np.ndarray
    ) -> str:
        """Generate human-readable anomaly explanation using FeatureIndices."""
        top_indices = np.argsort(feature_errors)[-5:][::-1]

        explanations = []
        feature_descriptions = {
            FeatureIndices.SRC_IP: "source IP",
            FeatureIndices.DST_IP: "destination IP",
            FeatureIndices.SRC_PORT: "source port",
            FeatureIndices.DST_PORT: "destination port",
            FeatureIndices.PROTOCOL: "protocol",
            FeatureIndices.SEVERITY: "severity",
            FeatureIndices.BYTES_SENT: "bytes sent",
            FeatureIndices.BYTES_RECEIVED: "bytes received",
            FeatureIndices.PACKETS_SENT: "packets sent",
            FeatureIndices.PACKETS_RECEIVED: "packets received",
            FeatureIndices.HOUR: "hour of day",
            FeatureIndices.HTTP_METHOD: "HTTP method",
            FeatureIndices.HTTP_RESPONSE_CODE: "HTTP response code",
            FeatureIndices.DNS_QUERY_LENGTH: "DNS query length",
        }

        for idx in top_indices:
            if FeatureIndices.EVENT_TYPE_START <= idx <= FeatureIndices.EVENT_TYPE_END:
                explanations.append(f"unusual event type pattern (dim {idx})")
            elif idx in feature_descriptions:
                desc = feature_descriptions[idx]
                orig_val = original[idx] if idx < len(original) else 0
                recon_val = reconstructed[idx] if idx < len(reconstructed) else 0
                deviation = abs(orig_val - recon_val)
                if deviation > 0.1:
                    explanations.append(
                        f"anomalous {desc} (deviation: {deviation:.3f})"
                    )

        if not explanations:
            explanations.append("general reconstruction error detected")

        return " | ".join(explanations[:3])

    def calibrate_threshold(
        self, normal_data: List[List[Dict[str, Any]]], percentile: float = 99.0
    ) -> float:
        """Calibrate threshold using normal data."""
        scores = []
        for sequence in normal_data:
            result = self.detect(sequence, threshold=1.0)
            scores.append(result.anomaly_score)

        self.threshold = np.percentile(scores, percentile)
        logger.info(
            "threshold_calibrated",
            threshold=self.threshold,
            percentile=percentile,
            samples=len(scores),
        )
        return self.threshold


# ═══════════════════════════════════════════════════════════════════════════
# DIFFUSION MODEL FOR ANOMALY DETECTION (State-of-the-Art)
# ═══════════════════════════════════════════════════════════════════════════

class DiffusionAnomalyDetector:
    """
    Diffusion Model for anomaly detection.
    
    Utilise un Denoising Diffusion Probabilistic Model (DDPM) pour
    détecter les anomalies par reconstruction après diffusion inverse.
    
    Principe :
    1. Ajout de bruit gaussien aux données (forward diffusion)
    2. Apprentissage du débruiteur (reverse diffusion)
    3. Les anomalies ont une erreur de reconstruction élevée
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 256,
        num_timesteps: int = 100,
        beta_start: float = 1e-4,
        beta_end: float = 0.02,
        device: Optional[torch.device] = None,
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_timesteps = num_timesteps
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Noise schedule (linear)
        self.betas = torch.linspace(beta_start, beta_end, num_timesteps, device=self.device)
        self.alphas = 1.0 - self.betas
        self.alpha_bars = torch.cumprod(self.alphas, dim=0)
        
        # U-Net like denoiser
        self.denoiser = self._build_denoiser().to(self.device)
        self.optimizer = torch.optim.AdamW(self.denoiser.parameters(), lr=1e-4, weight_decay=1e-5)
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(self.optimizer, T_max=1000)
        
        self.trained = False
        self.threshold = 0.5
        self.feature_names: Optional[List[str]] = None
    
    def _build_denoiser(self) -> nn.Module:
        """Build U-Net like denoiser with time embedding."""
        class TimeEmbedding(nn.Module):
            def __init__(self, dim: int):
                super().__init__()
                self.dim = dim
                self.mlp = nn.Sequential(
                    nn.Linear(dim, dim * 4),
                    nn.SiLU(),
                    nn.Linear(dim * 4, dim),
                )
            
            def forward(self, t: torch.Tensor) -> torch.Tensor:
                half_dim = self.dim // 2
                emb = torch.log(torch.tensor(10000.0)) / (half_dim - 1)
                emb = torch.exp(torch.arange(half_dim, device=t.device) * -emb)
                emb = t[:, None].float() * emb[None, :]
                emb = torch.cat([torch.sin(emb), torch.cos(emb)], dim=-1)
                return self.mlp(emb)
        
        class Denoiser(nn.Module):
            def __init__(self, input_dim: int, hidden_dim: int, time_dim: int = 128):
                super().__init__()
                self.time_embed = TimeEmbedding(time_dim)
                
                # Encoder
                self.enc1 = nn.Linear(input_dim + time_dim, hidden_dim)
                self.enc2 = nn.Linear(hidden_dim, hidden_dim * 2)
                self.enc3 = nn.Linear(hidden_dim * 2, hidden_dim * 2)
                
                # Bottleneck
                self.bottleneck = nn.Sequential(
                    nn.Linear(hidden_dim * 2, hidden_dim * 2),
                    nn.SiLU(),
                    nn.Dropout(0.1),
                    nn.Linear(hidden_dim * 2, hidden_dim * 2),
                )
                
                # Decoder
                self.dec1 = nn.Linear(hidden_dim * 4, hidden_dim * 2)
                self.dec2 = nn.Linear(hidden_dim * 2, hidden_dim)
                self.dec3 = nn.Linear(hidden_dim, input_dim)
                
                self.norm1 = nn.LayerNorm(hidden_dim)
                self.norm2 = nn.LayerNorm(hidden_dim * 2)
                self.dropout = nn.Dropout(0.1)
            
            def forward(self, x: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
                t_emb = self.time_embed(t)
                
                # Concatenate time embedding
                t_expanded = t_emb.expand(x.shape[0], -1)
                h = torch.cat([x, t_expanded], dim=-1)
                
                # Encoder
                h1 = F.silu(self.enc1(h))
                h1 = self.norm1(h1)
                h2 = F.silu(self.enc2(h1))
                h2 = self.norm2(h2)
                h3 = F.silu(self.enc3(h2))
                
                # Bottleneck
                h_bn = self.bottleneck(h3)
                
                # Decoder with skip connections
                h = torch.cat([h_bn, h3], dim=-1)
                h = F.silu(self.dec1(h))
                h = self.dropout(h)
                h = torch.cat([h, h2], dim=-1)
                h = F.silu(self.dec2(h))
                h = self.dropout(h)
                h = self.dec3(h)
                
                return h
        
        return Denoiser(self.input_dim, self.hidden_dim)
    
    def _add_noise(self, x: torch.Tensor, timesteps: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Add noise to data according to diffusion schedule."""
        noise = torch.randn_like(x)
        sqrt_alpha_bar = torch.sqrt(self.alpha_bars[timesteps]).view(-1, 1)
        sqrt_one_minus_alpha_bar = torch.sqrt(1.0 - self.alpha_bars[timesteps]).view(-1, 1)
        noisy_x = sqrt_alpha_bar * x + sqrt_one_minus_alpha_bar * noise
        return noisy_x, noise
    
    def train_step(self, x: torch.Tensor) -> Dict[str, float]:
        """Single training step."""
        self.denoiser.train()
        self.optimizer.zero_grad()
        
        batch_size = x.shape[0]
        timesteps = torch.randint(0, self.num_timesteps, (batch_size,), device=self.device)
        
        noisy_x, noise = self._add_noise(x, timesteps)
        predicted_noise = self.denoiser(noisy_x, timesteps.float())
        
        loss = F.mse_loss(predicted_noise, noise)
        
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.denoiser.parameters(), 1.0)
        self.optimizer.step()
        self.scheduler.step()
        
        return {"loss": loss.item(), "lr": self.scheduler.get_last_lr()[0]}
    
    def train(self, data: torch.Tensor, epochs: int = 100, batch_size: int = 64) -> Dict[str, Any]:
        """Train the diffusion model."""
        dataset = torch.utils.data.TensorDataset(data)
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        logger.info(f"Training Diffusion Model for {epochs} epochs...")
        losses = []
        
        for epoch in range(epochs):
            epoch_losses = []
            for batch in dataloader:
                x = batch[0].to(self.device)
                loss_dict = self.train_step(x)
                epoch_losses.append(loss_dict["loss"])
            
            avg_loss = np.mean(epoch_losses)
            losses.append(avg_loss)
            
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: loss={avg_loss:.6f}, lr={loss_dict['lr']:.6f}")
        
        self.trained = True
        logger.info(f"Diffusion Model trained: final_loss={losses[-1]:.6f}")
        
        return {
            "status": "trained",
            "epochs": epochs,
            "final_loss": losses[-1],
            "loss_history": losses,
        }
    
    @torch.no_grad()
    def detect(self, x: torch.Tensor) -> AnomalyDetectionResult:
        """
        Detect anomalies using diffusion reconstruction.
        Higher reconstruction error = more anomalous.
        """
        start_time = time.time()
        
        self.denoiser.eval()
        x = x.to(self.device)
        
        # Forward diffusion to a moderate timestep
        t = torch.full((x.shape[0],), self.num_timesteps // 2, device=self.device, dtype=torch.long)
        noisy_x, _ = self._add_noise(x, t)
        
        # Reverse diffusion (denoise)
        reconstructed = noisy_x.clone()
        for timestep in range(t[0].item(), 0, -1):
            t_tensor = torch.full((x.shape[0],), timestep, device=self.device, dtype=torch.float)
            predicted_noise = self.denoiser(reconstructed, t_tensor)
            
            beta = self.betas[timestep - 1]
            alpha = self.alphas[timestep - 1]
            alpha_bar = self.alpha_bars[timestep - 1]
            
            if timestep > 1:
                noise = torch.randn_like(reconstructed)
            else:
                noise = torch.zeros_like(reconstructed)
            
            reconstructed = (1 / torch.sqrt(alpha)) * (
                reconstructed - (beta / torch.sqrt(1 - alpha_bar)) * predicted_noise
            ) + torch.sqrt(beta) * noise
        
        # Compute reconstruction error
        reconstruction_error = F.mse_loss(reconstructed, x, reduction='none').mean(dim=-1)
        total_error = reconstruction_error.mean().item()
        
        # Feature-wise errors
        feature_errors = F.mse_loss(reconstructed, x, reduction='none').mean(dim=0).cpu().numpy()
        
        # Anomaly score
        anomaly_score = float(1.0 - torch.exp(-reconstruction_error.mean()).item())
        is_anomaly = anomaly_score > self.threshold
        
        # Explanation
        explanation = None
        if is_anomaly and self.feature_names:
            top_features = np.argsort(feature_errors)[-5:][::-1]
            explanations = []
            for idx in top_features:
                if idx < len(self.feature_names):
                    explanations.append(
                        f"diffusion anomaly in {self.feature_names[idx]} "
                        f"(err={feature_errors[idx]:.4f})"
                    )
            explanation = " | ".join(explanations[:3])
        
        feature_scores = {}
        if self.feature_names:
            for i, name in enumerate(self.feature_names[:len(feature_errors)]):
                feature_scores[name] = float(feature_errors[i])
        
        inference_time = (time.time() - start_time) * 1000
        
        return AnomalyDetectionResult(
            anomaly_score=anomaly_score,
            reconstruction_error=total_error,
            is_anomaly=is_anomaly,
            threshold_used=self.threshold,
            feature_scores=feature_scores if feature_scores else None,
            explanation=explanation,
            inference_time_ms=inference_time,
        )
    
    def calibrate_threshold(self, normal_data: torch.Tensor, percentile: float = 95.0) -> float:
        """Calibrate threshold using normal data."""
        scores = []
        for i in range(0, len(normal_data), 64):
            batch = normal_data[i:i+64].to(self.device)
            result = self.detect(batch)
            scores.append(result.anomaly_score)
        
        self.threshold = float(np.percentile(scores, percentile))
        logger.info(f"Diffusion threshold calibrated: {self.threshold:.4f} (p{percentile})")
        return self.threshold
    
    def generate_samples(self, num_samples: int = 10) -> torch.Tensor:
        """Generate synthetic samples using the diffusion model (reverse process)."""
        self.denoiser.eval()
        
        # Start from pure noise
        samples = torch.randn(num_samples, self.input_dim, device=self.device)
        
        # Reverse diffusion
        for timestep in range(self.num_timesteps - 1, 0, -1):
            t_tensor = torch.full((num_samples,), timestep, device=self.device, dtype=torch.float)
            predicted_noise = self.denoiser(samples, t_tensor)
            
            beta = self.betas[timestep - 1]
            alpha = self.alphas[timestep - 1]
            alpha_bar = self.alpha_bars[timestep - 1]
            
            if timestep > 1:
                noise = torch.randn_like(samples)
            else:
                noise = torch.zeros_like(samples)
            
            samples = (1 / torch.sqrt(alpha)) * (
                samples - (beta / torch.sqrt(1 - alpha_bar)) * predicted_noise
            ) + torch.sqrt(beta) * noise
        
        return samples.cpu()


def create_default_detector(use_diffusion: bool = False) -> Union[AnomalyDetector, DiffusionAnomalyDetector]:
    """Create a detector with sensible defaults."""
    if use_diffusion:
        detector = DiffusionAnomalyDetector()
        logger.info("Created DiffusionAnomalyDetector (state-of-the-art)")
        return detector
    detector = AnomalyDetector(use_isolation_forest=True)
    return detector
