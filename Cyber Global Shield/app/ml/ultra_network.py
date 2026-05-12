&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&²²²²²²²é"'''(rrrrrrrrrrrr)"""
Cyber Global Shield — Ultra-Pointer Network & Packet Analysis Module (Niveau 8)
================================================================================

4 modèles de pointe pour l'analyse réseau :

1. 1D-CNN + Attention — Dosovitskiy adapté — Analyse de paquets bruts
2. Flow-based GNN — Graph Neural Network pour flux réseau
3. Self-Supervised Learning (BYOL, SimSiam) — Représentation de trafic
4. Autoencoder + Transformer — Compression et détection d'anomalies

Chaque module peut fonctionner indépendamment ou via l'ensemble réseau.
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
class NetworkResult:
    """Résultat d'analyse réseau unifié."""
    score: float
    is_malicious: bool
    confidence: float
    analysis_type: str  # "packet", "flow", "ssl", "autoencoder"
    model_name: str
    explanation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    inference_time_ms: float = 0.0


@dataclass
class FlowGraph:
    """Graphe de flux réseau."""
    nodes: List[Dict[str, Any]]  # IPs, ports, protocoles
    edges: List[Tuple[int, int, float]]  # (src, dst, weight)
    features: np.ndarray  # features des nœuds
    timestamps: Optional[np.ndarray] = None
    labels: Optional[np.ndarray] = None


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: 1D-CNN + ATTENTION — Analyse de Paquets Bruts
# ═══════════════════════════════════════════════════════════════════════════

class PacketConvBlock(nn.Module):
    """Bloc convolutif 1D avec attention pour paquets."""

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int = 7,
        stride: int = 1,
        padding: int = 3,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.conv = nn.Conv1d(in_channels, out_channels, kernel_size, stride, padding, bias=False)
        self.bn = nn.BatchNorm1d(out_channels)
        self.silu = nn.SiLU()
        self.se = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Conv1d(out_channels, out_channels // 4, 1),
            nn.SiLU(),
            nn.Conv1d(out_channels // 4, out_channels, 1),
            nn.Sigmoid(),
        )
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        x = self.conv(x)
        x = self.bn(x)
        x = self.silu(x)
        x = x * self.se(x)
        if residual.shape == x.shape:
            x = x + residual
        return self.dropout(x)


class PacketAttention(nn.Module):
    """Mécanisme d'attention multi-tête pour paquets."""

    def __init__(self, embed_dim: int = 256, n_heads: int = 8, dropout: float = 0.1):
        super().__init__()
        self.attn = nn.MultiheadAttention(embed_dim, n_heads, dropout=dropout, batch_first=True)
        self.norm = nn.LayerNorm(embed_dim)
        self.ffn = nn.Sequential(
            nn.Linear(embed_dim, embed_dim * 4),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim * 4, embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.attn(self.norm(x), self.norm(x), self.norm(x))[0]
        x = x + self.ffn(self.norm(x))
        return x


class PacketCNNTransformer(nn.Module):
    """
    1D-CNN + Attention pour analyse de paquets bruts.
    Inspiré de Dosovitskiy et al. 2020, adapté aux séquences de paquets.
    """

    def __init__(
        self,
        input_dim: int = 1500,  # Taille max d'un paquet Ethernet
        packet_dim: int = 256,
        n_conv_layers: int = 5,
        n_attn_layers: int = 4,
        n_heads: int = 8,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_proj = nn.Conv1d(1, packet_dim, kernel_size=3, stride=1, padding=1)

        # CNN blocks
        self.conv_blocks = nn.ModuleList([
            PacketConvBlock(packet_dim, packet_dim, dropout=dropout)
            for _ in range(n_conv_layers)
        ])

        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.zeros(1, input_dim, packet_dim))
        nn.init.trunc_normal_(self.pos_encoding, std=0.02)

        # CLS token
        self.cls_token = nn.Parameter(torch.zeros(1, 1, packet_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)

        # Attention layers
        self.attn_layers = nn.ModuleList([
            PacketAttention(packet_dim, n_heads, dropout)
            for _ in range(n_attn_layers)
        ])

        self.norm = nn.LayerNorm(packet_dim)
        self.head = nn.Sequential(
            nn.Linear(packet_dim, packet_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(packet_dim // 2, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 1, T) — paquet brut
        x = self.input_proj(x)  # (B, D, T)
        x = x.transpose(1, 2)  # (B, T, D)

        for conv in self.conv_blocks:
            x = conv(x.transpose(1, 2)).transpose(1, 2)

        # Add positional encoding
        x = x + self.pos_encoding[:, :x.size(1), :]

        # Add CLS token
        B = x.shape[0]
        cls_token = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_token, x], dim=1)

        # Attention layers
        for attn in self.attn_layers:
            x = attn(x)

        x = self.norm(x)
        cls_out = x[:, 0]
        logits = self.head(cls_out)
        return logits

    def predict(self, x: torch.Tensor) -> NetworkResult:
        """Prédiction sur un paquet brut."""
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return NetworkResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="packet",
            model_name="PacketCNNTransformer",
            explanation=f"Packet analysis: malicious_prob={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "PacketCNNTransformer",
            "n_conv_layers": len(self.conv_blocks),
            "n_attn_layers": len(self.attn_layers),
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: FLOW-BASED GNN — Analyse de Flux Réseau
# ═══════════════════════════════════════════════════════════════════════════

class FlowGATLayer(nn.Module):
    """Graph Attention Network layer pour flux réseau."""

    def __init__(self, in_dim: int, out_dim: int, n_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.n_heads = n_heads
        self.head_dim = out_dim // n_heads
        self.scale = self.head_dim ** -0.5

        self.W_q = nn.Linear(in_dim, out_dim, bias=False)
        self.W_k = nn.Linear(in_dim, out_dim, bias=False)
        self.W_v = nn.Linear(in_dim, out_dim, bias=False)
        self.W_o = nn.Linear(out_dim, out_dim)

        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        x: torch.Tensor,  # (N, in_dim)
        adj: torch.Tensor,  # (N, N) — adjacency matrix
        edge_weights: Optional[torch.Tensor] = None,  # (N, N)
    ) -> torch.Tensor:
        N = x.shape[0]

        Q = self.W_q(x).view(N, self.n_heads, self.head_dim)  # (N, H, D)
        K = self.W_k(x).view(N, self.n_heads, self.head_dim)
        V = self.W_v(x).view(N, self.n_heads, self.head_dim)

        # Attention scores
        attn = torch.einsum('nhd,mhd->nhm', Q, K) * self.scale  # (N, N, H)

        # Mask by adjacency
        attn = attn.masked_fill(adj.unsqueeze(-1) == 0, float('-inf'))

        # Edge weights
        if edge_weights is not None:
            attn = attn + edge_weights.unsqueeze(-1)

        attn = F.softmax(attn, dim=1)
        attn = self.dropout(attn)

        # Weighted sum
        out = torch.einsum('nhm,mhd->nhd', attn, V)  # (N, H, D)
        out = out.reshape(N, -1)  # (N, out_dim)
        out = self.W_o(out)
        out = F.elu(out)
        return out


class FlowGNN(nn.Module):
    """
    Flow-based Graph Neural Network pour analyse de flux réseau.
    Détecte les communications malveillantes via la topologie du réseau.
    """

    def __init__(
        self,
        node_dim: int = 32,
        hidden_dim: int = 128,
        n_layers: int = 3,
        n_heads: int = 4,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.node_encoder = nn.Sequential(
            nn.Linear(node_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        self.gat_layers = nn.ModuleList([
            FlowGATLayer(hidden_dim, hidden_dim, n_heads, dropout)
            for _ in range(n_layers)
        ])

        self.temporal_proj = nn.Linear(hidden_dim, hidden_dim)

        self.global_pool = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
        )

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, n_classes),
        )

    def forward(
        self,
        x: torch.Tensor,  # (N, node_dim)
        adj: torch.Tensor,  # (N, N)
        timestamps: Optional[torch.Tensor] = None,  # (N,)
        batch: Optional[torch.Tensor] = None,  # (N,)
    ) -> torch.Tensor:
        x = self.node_encoder(x)

        for gat in self.gat_layers:
            x = gat(x, adj)

        # Temporal features
        if timestamps is not None:
            temporal_feat = self.temporal_proj(x)
            x = x + temporal_feat * timestamps.unsqueeze(-1)

        # Global pooling
        if batch is not None:
            n_graphs = batch.max().item() + 1
            graph_feats = []
            for i in range(n_graphs):
                mask = batch == i
                graph_feat = x[mask].mean(dim=0)
                graph_feats.append(graph_feat)
            x_pooled = torch.stack(graph_feats)
        else:
            x_pooled = x.mean(dim=0, keepdim=True)

        x_pooled = self.global_pool(x_pooled)
        logits = self.classifier(x_pooled)
        return logits

    def predict(self, graph: FlowGraph) -> NetworkResult:
        """Prédiction sur un graphe de flux réseau."""
        with torch.no_grad():
            x = torch.from_numpy(graph.features).float()
            N = len(graph.nodes)
            adj = torch.zeros((N, N))
            for i, j, w in graph.edges:
                adj[i, j] = w
                adj[j, i] = w

            timestamps = None
            if graph.timestamps is not None:
                timestamps = torch.from_numpy(graph.timestamps).float()

            logits = self.forward(x, adj, timestamps)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return NetworkResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="flow",
            model_name="FlowGNN",
            explanation=f"Flow graph analysis: malicious_prob={score:.4f}",
            metadata={
                "n_nodes": N,
                "n_edges": len(graph.edges),
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "FlowGNN",
            "n_layers": len(self.gat_layers),
            "hidden_dim": self.node_encoder[0].out_features,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: SELF-SUPERVISED LEARNING (BYOL + SimSiam)
# ═══════════════════════════════════════════════════════════════════════════

class TrafficEncoder(nn.Module):
    """Encoder pour représentations de trafic réseau."""

    def __init__(self, input_dim: int = 256, proj_dim: int = 128):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
        )
        self.projection = nn.Sequential(
            nn.Linear(256, proj_dim),
            nn.BatchNorm1d(proj_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.encoder(x)
        z = self.projection(h)
        return F.normalize(z, dim=1)


class TrafficBYOL(nn.Module):
    """
    Bootstrap Your Own Latent (BYOL) — Grill et al. 2020.
    Apprentissage auto-supervisé de représentations de trafic réseau.
    """

    def __init__(
        self,
        input_dim: int = 256,
        proj_dim: int = 128,
        hidden_dim: int = 512,
        momentum: float = 0.996,
    ):
        super().__init__()
        self.momentum = momentum

        # Online network
        self.online_encoder = TrafficEncoder(input_dim, proj_dim)
        self.predictor = nn.Sequential(
            nn.Linear(proj_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, proj_dim),
        )

        # Target network (momentum updated)
        self.target_encoder = TrafficEncoder(input_dim, proj_dim)
        for param in self.target_encoder.parameters():
            param.requires_grad = False

        self._init_target()

    def _init_target(self):
        for param_q, param_k in zip(
            self.online_encoder.parameters(), self.target_encoder.parameters()
        ):
            param_k.data.copy_(param_q.data)

    @torch.no_grad()
    def _momentum_update(self):
        for param_q, param_k in zip(
            self.online_encoder.parameters(), self.target_encoder.parameters()
        ):
            param_k.data = param_k.data * self.momentum + param_q.data * (1 - self.momentum)

    def forward(self, x1: torch.Tensor, x2: torch.Tensor) -> torch.Tensor:
        # x1, x2: deux vues augmentées du même trafic
        z1 = self.online_encoder(x1)
        z2 = self.online_encoder(x2)
        p1 = self.predictor(z1)
        p2 = self.predictor(z2)

        with torch.no_grad():
            self._momentum_update()
            z1_target = self.target_encoder(x1)
            z2_target = self.target_encoder(x2)

        # BYOL loss (negative cosine similarity)
        loss = 2.0 - F.cosine_similarity(p1, z2_target, dim=-1).mean() \
               - F.cosine_similarity(p2, z1_target, dim=-1).mean()

        return loss

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode du trafic en embedding."""
        with torch.no_grad():
            z = self.online_encoder(x)
        return z

    def predict(self, x: torch.Tensor, reference: torch.Tensor) -> NetworkResult:
        """Détection d'anomalies par similarité."""
        z = self.encode(x)
        z_ref = self.encode(reference)
        sim = F.cosine_similarity(z, z_ref, dim=1)
        score = 1.0 - float(sim.mean().item())

        return NetworkResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=1.0 - abs(score - 0.5) * 2,
            analysis_type="ssl",
            model_name="TrafficBYOL",
            explanation=f"BYOL traffic analysis: anomaly_score={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "TrafficBYOL",
            "proj_dim": self.online_encoder.projection[0].out_features,
            "momentum": self.momentum,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: AUTOENCODER + TRANSFORMER — Compression & Détection
# ═══════════════════════════════════════════════════════════════════════════

class TrafficAutoencoderTransformer(nn.Module):
    """
    Autoencoder + Transformer pour compression et détection d'anomalies réseau.
    Combine un autoencoder convolutif avec un Transformer pour la modélisation
    des dépendances longues.
    """

    def __init__(
        self,
        input_dim: int = 1500,
        latent_dim: int = 64,
        hidden_dim: int = 256,
        n_heads: int = 8,
        n_layers: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_dim = input_dim

        # Encoder
        self.encoder_conv = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=5, stride=2, padding=2),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Conv1d(32, 64, kernel_size=5, stride=2, padding=2),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
        )

        # Calculate encoded length
        self.encoded_len = input_dim // 8
        self.encoder_proj = nn.Linear(128, hidden_dim)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=n_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, n_layers)

        # Latent bottleneck
        self.latent_proj = nn.Linear(hidden_dim, latent_dim)
        self.latent_norm = nn.LayerNorm(latent_dim)

        # Decoder
        self.decoder_proj = nn.Linear(latent_dim, hidden_dim)
        self.decoder_transformer = nn.TransformerEncoder(encoder_layer, n_layers // 2)

        self.decoder_conv = nn.Sequential(
            nn.ConvTranspose1d(hidden_dim, 128, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.ConvTranspose1d(128, 64, kernel_size=5, stride=2, padding=2, output_padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.ConvTranspose1d(64, 32, kernel_size=5, stride=2, padding=2, output_padding=1),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Conv1d(32, 1, kernel_size=3, padding=1),
        )

        # Anomaly head
        self.anomaly_head = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 2),
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        # x: (B, 1, T)
        # Encode
        h = self.encoder_conv(x)  # (B, 128, T/8)
        h = h.transpose(1, 2)  # (B, T/8, 128)
        h = self.encoder_proj(h)  # (B, T/8, hidden_dim)

        # Transformer
        h = self.transformer(h)

        # Latent
        latent = h.mean(dim=1)  # (B, hidden_dim)
        latent = self.latent_proj(latent)  # (B, latent_dim)
        latent = self.latent_norm(latent)

        # Decode
        d = self.decoder_proj(latent).unsqueeze(1)  # (B, 1, hidden_dim)
        d = d.expand(-1, self.encoded_len, -1)  # (B, T/8, hidden_dim)
        d = self.decoder_transformer(d)
        d = d.transpose(1, 2)  # (B, hidden_dim, T/8)
        d = self.decoder_conv(d)  # (B, 1, T)

        # Anomaly score
        anomaly_logits = self.anomaly_head(latent)  # (B, 2)

        return d, latent, anomaly_logits

    def compute_reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute reconstruction error for anomaly detection."""
        recon, latent, _ = self.forward(x)
        error = F.mse_loss(recon, x, reduction='none')
        error = error.view(x.shape[0], -1).mean(dim=1)
        return error

    def predict(self, x: torch.Tensor) -> NetworkResult:
        """Détection d'anomalie par erreur de reconstruction."""
        with torch.no_grad():
            recon, latent, anomaly_logits = self.forward(x)
            recon_error = F.mse_loss(recon, x, reduction='none').view(x.shape[0], -1).mean(dim=1)
            anomaly_probs = F.softmax(anomaly_logits, dim=-1)

            score = float(anomaly_probs[0, 1].item())
            confidence = float(anomaly_probs.max().item())
            recon_score = float(recon_error[0].item())

        return NetworkResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="autoencoder",
            model_name="TrafficAutoencoderTransformer",
            explanation=f"AE-Transformer analysis: anomaly_prob={score:.4f}, recon_error={recon_score:.4f}",
            metadata={
                "reconstruction_error": recon_score,
                "latent_dim": latent.shape[-1],
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "TrafficAutoencoderTransformer",
            "latent_dim": self.latent_proj.out_features,
            "n_transformer_layers": len(self.transformer.layers),
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK ENSEMBLE
# ═══════════════════════════════════════════════════════════════════════════

class NetworkEnsemble:
    """
    Ensemble réseau qui combine tous les analyseurs.
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
            "network_ensemble_initialized",
            n_models=len(models),
            weights=self.weights,
        )

    def analyze_packet(self, x: torch.Tensor) -> NetworkResult:
        """Analyse un paquet brut avec PacketCNNTransformer."""
        results = []
        if "packet" in self.models:
            r = self.models["packet"].predict(x)
            results.append(r)
        return self._combine_results(results, "packet")

    def analyze_flow(self, graph: FlowGraph) -> NetworkResult:
        """Analyse un graphe de flux avec FlowGNN."""
        results = []
        if "flow" in self.models:
            r = self.models["flow"].predict(graph)
            results.append(r)
        return self._combine_results(results, "flow")

    def analyze_traffic(
        self, x: torch.Tensor, reference: Optional[torch.Tensor] = None
    ) -> NetworkResult:
        """Analyse du trafic avec BYOL et Autoencoder."""
        results = []

        if "byol" in self.models and reference is not None:
            r = self.models["byol"].predict(x, reference)
            results.append(r)

        if "autoencoder" in self.models:
            r = self.models["autoencoder"].predict(x)
            results.append(r)

        return self._combine_results(results, "traffic")

    def _combine_results(
        self, results: List[NetworkResult], analysis_type: str
    ) -> NetworkResult:
        """Combine les résultats pondérés."""
        if not results:
            return NetworkResult(
                score=0.0,
                is_malicious=False,
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

        result = NetworkResult(
            score=final_score,
            is_malicious=final_score > 0.5,
            confidence=avg_confidence,
            analysis_type=analysis_type,
            model_name="network_ensemble",
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

def create_ultra_network(
    packet_dim: int = 256,
    flow_node_dim: int = 32,
    traffic_dim: int = 256,
    device: str = "cpu",
    use_packet: bool = True,
    use_flow: bool = True,
    use_byol: bool = True,
    use_autoencoder: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système d'analyse réseau complet Niveau 8.

    Args:
        packet_dim: Dimension des embeddings de paquets
        flow_node_dim: Dimension des nœuds de flux
        traffic_dim: Dimension du trafic pour BYOL/AE
        device: "cpu" ou "cuda"
        use_packet: Activer PacketCNNTransformer
        use_flow: Activer FlowGNN
        use_byol: Activer TrafficBYOL
        use_autoencoder: Activer TrafficAutoencoderTransformer

    Returns:
        Dict avec tous les composants
    """
    models = {}

    if use_packet:
        models["packet"] = PacketCNNTransformer(packet_dim=packet_dim)
        logger.info("✅ PacketCNNTransformer initialized")

    if use_flow:
        models["flow"] = FlowGNN(node_dim=flow_node_dim)
        logger.info("✅ FlowGNN initialized")

    if use_byol:
        models["byol"] = TrafficBYOL(input_dim=traffic_dim)
        logger.info("✅ TrafficBYOL initialized")

    if use_autoencoder:
        models["autoencoder"] = TrafficAutoencoderTransformer(input_dim=1500)
        logger.info("✅ TrafficAutoencoderTransformer initialized")

    ensemble = NetworkEnsemble(models=models)
    logger.info("✅ NetworkEnsemble initialized")

    return {
        "models": models,
        "ensemble": ensemble,
        "config": {
            "packet_dim": packet_dim,
            "flow_node_dim": flow_node_dim,
            "traffic_dim": traffic_dim,
            "device": device,
            "n_models": len(models),
        },
    }


def create_ultra_network_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_network(
        use_packet=True,
        use_flow=False,
        use_byol=False,
        use_autoencoder=False,
    )


def create_ultra_network_full() -> Dict[str, Any]:
    """Version complète avec tous les analyseurs."""
    return create_ultra_network(
        use_packet=True,
        use_flow=True,
        use_byol=True,
        use_autoencoder=True,
    )


# Instance globale
ultra_network_system = create_ultra_network_full()


def get_ultra_network() -> Dict[str, Any]:
    """Get the global network analysis system instance."""
    return ultra_network_system
