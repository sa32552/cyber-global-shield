"""
Cyber Global Shield — Ultra-Pointer Forensics & Investigation Module (Niveau 7)
===============================================================================

5 modèles de pointe pour l'analyse forensics :

1. Vision Transformer (ViT) — Dosovitskiy et al. 2020 — Analyse d'images forensics
2. EfficientNet — Tan & Le 2019 — Détection deepfake optimisée
3. Audio Transformers (Wav2Vec2) — Baevski et al. 2020 — Analyse audio forensics
4. Graph-based Malware Analysis — Function Call Graphs avec GNN
5. Contrastive Learning (SimCLR, MoCo) — Similarité de malware

Chaque module peut fonctionner indépendamment ou via l'ensemble forensics.
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
class ForensicsResult:
    """Résultat d'analyse forensics unifié."""
    score: float
    is_malicious: bool
    confidence: float
    analysis_type: str  # "image", "audio", "graph", "contrastive"
    model_name: str
    explanation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    inference_time_ms: float = 0.0


@dataclass
class MalwareGraph:
    """Graphe d'appels de fonction d'un malware."""
    nodes: List[Dict[str, Any]]  # fonctions
    edges: List[Tuple[int, int]]  # appels
    features: np.ndarray  # features des nœuds
    labels: Optional[np.ndarray] = None


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: VISION TRANSFORMER (ViT) — Dosovitskiy et al. 2020
# ═══════════════════════════════════════════════════════════════════════════

class ViTPatchEmbedding(nn.Module):
    """Patch embedding pour Vision Transformer."""

    def __init__(
        self,
        img_size: int = 224,
        patch_size: int = 16,
        in_channels: int = 3,
        embed_dim: int = 768,
    ):
        super().__init__()
        self.img_size = img_size
        self.patch_size = patch_size
        self.n_patches = (img_size // patch_size) ** 2

        self.proj = nn.Conv2d(
            in_channels, embed_dim,
            kernel_size=patch_size, stride=patch_size,
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.proj(x)  # (B, embed_dim, H/p, W/p)
        x = x.flatten(2)  # (B, embed_dim, n_patches)
        x = x.transpose(1, 2)  # (B, n_patches, embed_dim)
        return x


class ViTBlock(nn.Module):
    """Transformer block avec attention multi-tête."""

    def __init__(
        self,
        embed_dim: int = 768,
        n_heads: int = 12,
        mlp_ratio: float = 4.0,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.norm1 = nn.LayerNorm(embed_dim)
        self.attn = nn.MultiheadAttention(embed_dim, n_heads, dropout=dropout, batch_first=True)
        self.norm2 = nn.LayerNorm(embed_dim)
        self.mlp = nn.Sequential(
            nn.Linear(embed_dim, int(embed_dim * mlp_ratio)),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(int(embed_dim * mlp_ratio), embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.attn(self.norm1(x), self.norm1(x), self.norm1(x))[0]
        x = x + self.mlp(self.norm2(x))
        return x


class VisionTransformer(nn.Module):
    """
    Vision Transformer (ViT) — Dosovitskiy et al. 2020.
    Utilisé pour l'analyse d'images forensics (deepfake, stéganographie, etc.).
    """

    def __init__(
        self,
        img_size: int = 224,
        patch_size: int = 16,
        in_channels: int = 3,
        embed_dim: int = 768,
        depth: int = 12,
        n_heads: int = 12,
        mlp_ratio: float = 4.0,
        dropout: float = 0.1,
        n_classes: int = 2,
    ):
        super().__init__()
        self.patch_embed = ViTPatchEmbedding(img_size, patch_size, in_channels, embed_dim)
        n_patches = self.patch_embed.n_patches

        # CLS token + position embedding
        self.cls_token = nn.Parameter(torch.zeros(1, 1, embed_dim))
        self.pos_embed = nn.Parameter(torch.zeros(1, n_patches + 1, embed_dim))
        self.pos_drop = nn.Dropout(dropout)

        # Transformer blocks
        self.blocks = nn.ModuleList([
            ViTBlock(embed_dim, n_heads, mlp_ratio, dropout)
            for _ in range(depth)
        ])

        self.norm = nn.LayerNorm(embed_dim)
        self.head = nn.Linear(embed_dim, n_classes)

        self._init_weights()

    def _init_weights(self):
        nn.init.trunc_normal_(self.pos_embed, std=0.02)
        nn.init.trunc_normal_(self.cls_token, std=0.02)
        self.apply(self._init_layer)

    def _init_layer(self, m):
        if isinstance(m, nn.Linear):
            nn.init.trunc_normal_(m.weight, std=0.02)
            if m.bias is not None:
                nn.init.zeros_(m.bias)
        elif isinstance(m, nn.LayerNorm):
            nn.init.ones_(m.weight)
            nn.init.zeros_(m.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B = x.shape[0]
        x = self.patch_embed(x)

        cls_token = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_token, x], dim=1)
        x = x + self.pos_embed
        x = self.pos_drop(x)

        for block in self.blocks:
            x = block(x)

        x = self.norm(x)
        cls_out = x[:, 0]  # CLS token
        logits = self.head(cls_out)
        return logits

    def predict(self, x: torch.Tensor) -> ForensicsResult:
        """Prédiction avec calibration."""
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())  # probabilité classe malveillante
            confidence = float(probs.max().item())

        return ForensicsResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="image",
            model_name="VisionTransformer",
            explanation=f"ViT forensic analysis: malicious_prob={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "VisionTransformer",
            "embed_dim": self.patch_embed.proj.out_channels,
            "depth": len(self.blocks),
            "n_heads": self.blocks[0].attn.num_heads if self.blocks else 0,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: EFFICIENTNET — Tan & Le 2019
# ═══════════════════════════════════════════════════════════════════════════

class MBConvBlock(nn.Module):
    """Mobile Inverted Bottleneck Conv — EfficientNet building block."""

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int = 3,
        stride: int = 1,
        expand_ratio: int = 6,
        se_ratio: float = 0.25,
        drop_rate: float = 0.2,
    ):
        super().__init__()
        self.use_residual = stride == 1 and in_channels == out_channels
        hidden_dim = in_channels * expand_ratio

        layers = []

        # Expansion phase
        if expand_ratio != 1:
            layers.append(nn.Conv2d(in_channels, hidden_dim, 1, bias=False))
            layers.append(nn.BatchNorm2d(hidden_dim))
            layers.append(nn.SiLU())

        # Depthwise convolution
        layers.append(nn.Conv2d(
            hidden_dim, hidden_dim, kernel_size,
            stride=stride, padding=kernel_size // 2,
            groups=hidden_dim, bias=False,
        ))
        layers.append(nn.BatchNorm2d(hidden_dim))
        layers.append(nn.SiLU())

        # Squeeze-and-Excitation
        se_dim = max(1, int(in_channels * se_ratio))
        self.se = nn.Sequential(
            nn.AdaptiveAvgPool2d(1),
            nn.Conv2d(hidden_dim, se_dim, 1),
            nn.SiLU(),
            nn.Conv2d(se_dim, hidden_dim, 1),
            nn.Sigmoid(),
        )

        # Output phase
        layers.append(nn.Conv2d(hidden_dim, out_channels, 1, bias=False))
        layers.append(nn.BatchNorm2d(out_channels))

        self.conv = nn.Sequential(*layers)
        self.dropout = nn.Dropout(drop_rate)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        x = self.conv(x)
        x = x * self.se(x)
        if self.use_residual:
            x = residual + x
        return self.dropout(x)


class EfficientNet(nn.Module):
    """
    EfficientNet — Tan & Le 2019.
    Optimisé pour la détection de deepfakes et l'analyse d'images forensics.
    """

    def __init__(
        self,
        width_mult: float = 1.0,
        depth_mult: float = 1.0,
        n_classes: int = 2,
        dropout_rate: float = 0.2,
    ):
        super().__init__()

        # EfficientNet-B0 config
        base_channels = 32
        config = [
            # (in_ch, out_ch, kernel, stride, expand, depth, se)
            (32, 16, 3, 1, 1, 1, 0.25),
            (16, 24, 3, 2, 6, 2, 0.25),
            (24, 40, 5, 2, 6, 2, 0.25),
            (40, 80, 3, 2, 6, 3, 0.25),
            (80, 112, 5, 1, 6, 3, 0.25),
            (112, 192, 5, 2, 6, 4, 0.25),
            (192, 320, 3, 1, 6, 1, 0.25),
        ]

        # Stem
        in_ch = int(base_channels * width_mult)
        self.stem = nn.Sequential(
            nn.Conv2d(3, in_ch, 3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(in_ch),
            nn.SiLU(),
        )

        # Blocks
        self.blocks = nn.ModuleList()
        for in_ch, out_ch, k, s, e, d, se in config:
            in_ch = int(in_ch * width_mult)
            out_ch = int(out_ch * width_mult)
            depth = max(1, int(d * depth_mult))
            for i in range(depth):
                stride = s if i == 0 else 1
                self.blocks.append(MBConvBlock(
                    in_ch if i == 0 else out_ch,
                    out_ch, k, stride, e, se,
                ))

        # Head
        final_ch = int(1280 * width_mult)
        self.head = nn.Sequential(
            nn.Conv2d(int(320 * width_mult), final_ch, 1, bias=False),
            nn.BatchNorm2d(final_ch),
            nn.SiLU(),
            nn.AdaptiveAvgPool2d(1),
            nn.Flatten(),
            nn.Dropout(dropout_rate),
            nn.Linear(final_ch, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.stem(x)
        for block in self.blocks:
            x = block(x)
        x = self.head(x)
        return x

    def predict(self, x: torch.Tensor) -> ForensicsResult:
        """Prédiction deepfake / image forensics."""
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return ForensicsResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="image",
            model_name="EfficientNet",
            explanation=f"EfficientNet deepfake analysis: malicious_prob={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "EfficientNet",
            "n_blocks": len(self.blocks),
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: AUDIO TRANSFORMER (Wav2Vec2-style) — Baevski et al. 2020
# ═══════════════════════════════════════════════════════════════════════════

class AudioFeatureExtractor(nn.Module):
    """Extraction de features audio avec convolutions 1D."""

    def __init__(
        self,
        input_dim: int = 80,  # MFCC features
        hidden_dim: int = 512,
        n_layers: int = 7,
    ):
        super().__init__()
        layers = []
        in_ch = 1
        for i in range(n_layers):
            out_ch = min(hidden_dim, 64 * (2 ** min(i, 4)))
            layers.append(
                nn.Conv1d(in_ch, out_ch, kernel_size=10, stride=5, padding=3)
            )
            layers.append(nn.GELU())
            layers.append(nn.GroupNorm(8, out_ch))
            in_ch = out_ch
        self.conv_layers = nn.Sequential(*layers)
        self.proj = nn.Linear(in_ch, hidden_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 1, T)
        x = self.conv_layers(x)  # (B, C, T')
        x = x.transpose(1, 2)  # (B, T', C)
        x = self.proj(x)  # (B, T', hidden_dim)
        return x


class AudioTransformer(nn.Module):
    """
    Audio Transformer (Wav2Vec2-style) — Baevski et al. 2020.
    Analyse audio forensics : détection de voix synthétiques, deepfake audio.
    """

    def __init__(
        self,
        input_dim: int = 80,
        hidden_dim: int = 512,
        n_heads: int = 8,
        n_layers: int = 12,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.feature_extractor = AudioFeatureExtractor(input_dim, hidden_dim)

        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.zeros(1, 500, hidden_dim))
        nn.init.trunc_normal_(self.pos_encoding, std=0.02)

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

        # CLS token
        self.cls_token = nn.Parameter(torch.zeros(1, 1, hidden_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)

        self.norm = nn.LayerNorm(hidden_dim)
        self.head = nn.Linear(hidden_dim, n_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 1, T) audio waveform or (B, T, input_dim) features
        if x.dim() == 3 and x.size(1) == 1:
            x = self.feature_extractor(x)
        elif x.dim() == 2:
            x = x.unsqueeze(1)
            x = self.feature_extractor(x)

        B, T, D = x.shape

        # Add CLS token
        cls_token = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_token, x], dim=1)

        # Add positional encoding
        x = x + self.pos_encoding[:, :x.size(1), :]

        # Transformer
        x = self.transformer(x)
        x = self.norm(x)

        # CLS token output
        cls_out = x[:, 0]
        logits = self.head(cls_out)
        return logits

    def predict(self, x: torch.Tensor) -> ForensicsResult:
        """Prédiction audio forensics."""
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return ForensicsResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="audio",
            model_name="AudioTransformer",
            explanation=f"Audio forensic analysis: synthetic_prob={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "AudioTransformer",
            "hidden_dim": self.feature_extractor.proj.in_features,
            "n_layers": len(self.transformer.layers),
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4: GRAPH-BASED MALWARE ANALYSIS (Function Call Graphs)
# ═══════════════════════════════════════════════════════════════════════════

class GraphConvLayer(nn.Module):
    """Graph Convolution layer with self-attention."""

    def __init__(self, in_dim: int, out_dim: int, dropout: float = 0.1):
        super().__init__()
        self.W = nn.Linear(in_dim, out_dim)
        self.self_attn = nn.Linear(in_dim, 1)
        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        x: torch.Tensor,  # (N, in_dim)
        adj: torch.Tensor,  # (N, N)
    ) -> torch.Tensor:
        # Self-attention weights
        attn_weights = torch.sigmoid(self.self_attn(x))  # (N, 1)

        # Message passing
        neighbor_msg = adj @ x  # (N, in_dim)

        # Combine self + neighbors with attention
        x_combined = attn_weights * x + (1 - attn_weights) * neighbor_msg
        x_out = self.W(x_combined)
        x_out = F.relu(x_out)
        x_out = self.dropout(x_out)
        return x_out


class MalwareGraphGNN(nn.Module):
    """
    Graph Neural Network pour analyse de malware basée sur les
    Function Call Graphs (FCG). Détecte les similarités structurelles
    entre familles de malware.
    """

    def __init__(
        self,
        node_dim: int = 64,
        hidden_dim: int = 128,
        n_layers: int = 3,
        n_classes: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.node_encoder = nn.Linear(node_dim, hidden_dim)

        self.convs = nn.ModuleList([
            GraphConvLayer(hidden_dim, hidden_dim, dropout)
            for _ in range(n_layers)
        ])

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
        batch: Optional[torch.Tensor] = None,  # (N,) batch indices
    ) -> torch.Tensor:
        x = self.node_encoder(x)

        for conv in self.convs:
            x = conv(x, adj)

        # Global pooling
        if batch is not None:
            # Mean pooling per graph
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

    def predict(self, graph: MalwareGraph) -> ForensicsResult:
        """Prédiction sur un graphe de malware."""
        with torch.no_grad():
            x = torch.from_numpy(graph.features).float()
            adj = torch.zeros((len(graph.nodes), len(graph.nodes)))
            for i, j in graph.edges:
                adj[i, j] = 1.0
                adj[j, i] = 1.0  # undirected

            logits = self.forward(x, adj)
            probs = F.softmax(logits, dim=-1)
            score = float(probs[0, 1].item())
            confidence = float(probs.max().item())

        return ForensicsResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=confidence,
            analysis_type="graph",
            model_name="MalwareGraphGNN",
            explanation=f"Graph malware analysis: malicious_prob={score:.4f}",
            metadata={
                "n_nodes": len(graph.nodes),
                "n_edges": len(graph.edges),
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "MalwareGraphGNN",
            "n_layers": len(self.convs),
            "hidden_dim": self.node_encoder.out_features,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5: CONTRASTIVE LEARNING (SimCLR + MoCo)
# ═══════════════════════════════════════════════════════════════════════════

class ContrastiveEncoder(nn.Module):
    """Encoder projection pour contrastive learning."""

    def __init__(self, input_dim: int, proj_dim: int = 128):
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


class ContrastiveLearning(nn.Module):
    """
    Contrastive Learning (SimCLR + MoCo-style).
    Utilisé pour la similarité de malware et la détection de variants.
    """

    def __init__(
        self,
        input_dim: int = 128,
        proj_dim: int = 128,
        temperature: float = 0.07,
        queue_size: int = 4096,
        momentum: float = 0.999,
    ):
        super().__init__()
        self.temperature = temperature
        self.queue_size = queue_size
        self.momentum = momentum

        # Encoder
        self.encoder_q = ContrastiveEncoder(input_dim, proj_dim)
        self.encoder_k = ContrastiveEncoder(input_dim, proj_dim)

        # Initialize momentum encoder
        for param_q, param_k in zip(
            self.encoder_q.parameters(), self.encoder_k.parameters()
        ):
            param_k.data.copy_(param_q.data)
            param_k.requires_grad = False

        # Queue
        self.register_buffer("queue", torch.randn(proj_dim, queue_size))
        self.queue = F.normalize(self.queue, dim=0)
        self.register_buffer("queue_ptr", torch.zeros(1, dtype=torch.long))

    @torch.no_grad()
    def _momentum_update(self):
        for param_q, param_k in zip(
            self.encoder_q.parameters(), self.encoder_k.parameters()
        ):
            param_k.data = param_k.data * self.momentum + param_q.data * (1 - self.momentum)

    @torch.no_grad()
    def _dequeue_and_enqueue(self, keys: torch.Tensor):
        batch_size = keys.shape[0]
        ptr = int(self.queue_ptr)
        self.queue[:, ptr:ptr + batch_size] = keys.T
        ptr = (ptr + batch_size) % self.queue_size
        self.queue_ptr[0] = ptr

    def forward(self, im_q: torch.Tensor, im_k: torch.Tensor) -> torch.Tensor:
        # Compute query features
        q = self.encoder_q(im_q)  # (N, proj_dim)

        # Compute key features
        with torch.no_grad():
            self._momentum_update()
            k = self.encoder_k(im_k)  # (N, proj_dim)

        # Contrastive loss (InfoNCE)
        l_pos = torch.einsum('nc,nc->n', q, k).unsqueeze(-1)  # (N, 1)
        l_neg = torch.einsum('nc,ck->nk', q, self.queue.clone().detach())  # (N, K)

        logits = torch.cat([l_pos, l_neg], dim=1) / self.temperature
        labels = torch.zeros(logits.shape[0], dtype=torch.long, device=logits.device)

        loss = F.cross_entropy(logits, labels)

        # Update queue
        self._dequeue_and_enqueue(k)

        return loss

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode une entrée en embedding contrastif."""
        with torch.no_grad():
            z = self.encoder_q(x)
        return z

    def compute_similarity(
        self, x1: torch.Tensor, x2: torch.Tensor
    ) -> float:
        """Compute cosine similarity between two samples."""
        z1 = self.encode(x1)
        z2 = self.encode(x2)
        sim = F.cosine_similarity(z1, z2, dim=1)
        return float(sim.mean().item())

    def predict(self, x: torch.Tensor, reference: torch.Tensor) -> ForensicsResult:
        """Prédiction basée sur la similarité avec un échantillon de référence."""
        sim = self.compute_similarity(x, reference)
        score = 1.0 - sim  # plus c'est différent, plus c'est suspect

        return ForensicsResult(
            score=score,
            is_malicious=score > 0.5,
            confidence=1.0 - abs(score - 0.5) * 2,
            analysis_type="contrastive",
            model_name="ContrastiveLearning",
            explanation=f"Contrastive similarity: sim={sim:.4f}, anomaly_score={score:.4f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "ContrastiveLearning",
            "proj_dim": self.encoder_q.projection[0].out_features,
            "queue_size": self.queue_size,
            "temperature": self.temperature,
            "n_params": sum(p.numel() for p in self.parameters()),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FORENSICS ENSEMBLE
# ═══════════════════════════════════════════════════════════════════════════

class ForensicsEnsemble:
    """
    Ensemble forensics qui combine tous les analyseurs.
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
            "forensics_ensemble_initialized",
            n_models=len(models),
            weights=self.weights,
        )

    def analyze_image(self, x: torch.Tensor) -> ForensicsResult:
        """Analyse une image avec ViT et EfficientNet."""
        results = []

        if "vit" in self.models:
            r = self.models["vit"].predict(x)
            results.append(r)

        if "efficientnet" in self.models:
            r = self.models["efficientnet"].predict(x)
            results.append(r)

        return self._combine_results(results, "image")

    def analyze_audio(self, x: torch.Tensor) -> ForensicsResult:
        """Analyse un échantillon audio."""
        results = []
        if "audio" in self.models:
            r = self.models["audio"].predict(x)
            results.append(r)
        return self._combine_results(results, "audio")

    def analyze_graph(self, graph: MalwareGraph) -> ForensicsResult:
        """Analyse un graphe de malware."""
        results = []
        if "graph" in self.models:
            r = self.models["graph"].predict(graph)
            results.append(r)
        return self._combine_results(results, "graph")

    def analyze_contrastive(
        self, x: torch.Tensor, reference: torch.Tensor
    ) -> ForensicsResult:
        """Analyse par similarité contrastive."""
        results = []
        if "contrastive" in self.models:
            r = self.models["contrastive"].predict(x, reference)
            results.append(r)
        return self._combine_results(results, "contrastive")

    def _combine_results(
        self, results: List[ForensicsResult], analysis_type: str
    ) -> ForensicsResult:
        """Combine les résultats pondérés."""
        if not results:
            return ForensicsResult(
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

        result = ForensicsResult(
            score=final_score,
            is_malicious=final_score > 0.5,
            confidence=avg_confidence,
            analysis_type=analysis_type,
            model_name="forensics_ensemble",
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

def create_ultra_forensics(
    img_size: int = 224,
    audio_dim: int = 80,
    graph_node_dim: int = 64,
    contrastive_dim: int = 128,
    device: str = "cpu",
    use_vit: bool = True,
    use_efficientnet: bool = True,
    use_audio: bool = True,
    use_graph: bool = True,
    use_contrastive: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système forensics complet Niveau 7.

    Args:
        img_size: Taille d'image pour ViT/EfficientNet
        audio_dim: Dimension des features audio
        graph_node_dim: Dimension des nœuds de graphe
        contrastive_dim: Dimension des embeddings contrastifs
        device: "cpu" ou "cuda"
        use_vit: Activer Vision Transformer
        use_efficientnet: Activer EfficientNet
        use_audio: Activer Audio Transformer
        use_graph: Activer Graph Malware Analysis
        use_contrastive: Activer Contrastive Learning
    
    Returns:
        Dict avec tous les composants
    """
    models = {}
    
    if use_vit:
        models["vit"] = VisionTransformer(img_size=img_size)
        logger.info("✅ VisionTransformer initialized")
    
    if use_efficientnet:
        models["efficientnet"] = EfficientNet()
        logger.info("✅ EfficientNet initialized")
    
    if use_audio:
        models["audio"] = AudioTransformer(input_dim=audio_dim)
        logger.info("✅ AudioTransformer initialized")
    
    if use_graph:
        models["graph"] = MalwareGraphGNN(node_dim=graph_node_dim)
        logger.info("✅ MalwareGraphGNN initialized")
    
    if use_contrastive:
        models["contrastive"] = ContrastiveLearning(input_dim=contrastive_dim)
        logger.info("✅ ContrastiveLearning initialized")
    
    ensemble = ForensicsEnsemble(models=models)
    logger.info("✅ ForensicsEnsemble initialized")
    
    return {
        "models": models,
        "ensemble": ensemble,
        "config": {
            "img_size": img_size,
            "audio_dim": audio_dim,
            "graph_node_dim": graph_node_dim,
            "contrastive_dim": contrastive_dim,
            "device": device,
            "n_models": len(models),
        },
    }


def create_ultra_forensics_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_forensics(
        use_vit=True,
        use_efficientnet=False,
        use_audio=False,
        use_graph=False,
        use_contrastive=False,
    )


def create_ultra_forensics_full() -> Dict[str, Any]:
    """Version complète avec tous les analyseurs."""
    return create_ultra_forensics(
        use_vit=True,
        use_efficientnet=True,
        use_audio=True,
        use_graph=True,
        use_contrastive=True,
    )


# Instance globale
ultra_forensics_system = create_ultra_forensics_full()


def get_ultra_forensics() -> Dict[str, Any]:
    """Get the global forensics system instance."""
    return ultra_forensics_system
