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


def create_default_detector() -> AnomalyDetector:
    """Create a detector with sensible defaults."""
    detector = AnomalyDetector(use_isolation_forest=True)
    return detector
