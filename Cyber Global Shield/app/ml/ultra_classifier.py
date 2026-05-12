"""
Cyber Global Shield — Ultra-Pointer Classification Module (Niveau 3)
====================================================================

4 modèles de classification de pointe coordonnés :

1. Hierarchical Attention Networks (HAN) — Attention hiérarchique pour logs/séquences
2. Prototypical Networks — Few-shot learning pour nouvelles menaces
3. Set Transformers — Attention pour ensembles non ordonnés (IPs, events)
4. Perceiver IO — DeepMind, architecture générique pour tout type de données

Chaque classifieur peut fonctionner indépendamment ou via l'ensemble.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field
from collections import deque
import structlog

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ClassificationResult:
    """Résultat de classification unifié."""
    class_id: int
    class_name: str
    probability: float
    confidence: float
    all_probabilities: Dict[str, float] = field(default_factory=dict)
    explanation: Optional[str] = None
    inference_time_ms: float = 0.0
    model_name: str = "unknown"


@dataclass
class ClassificationBatch:
    """Lot de classifications."""
    results: List[ClassificationResult]
    n_samples: int = 0
    avg_confidence: float = 0.0
    batch_inference_time_ms: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# 1. HIERARCHICAL ATTENTION NETWORKS (HAN)
# ═══════════════════════════════════════════════════════════════════════════

class WordAttention(nn.Module):
    """
    Word-level attention layer.
    
    Attend sur les mots d'une séquence pour produire un vecteur
    de phrase. Utilise un contexte vector learnable.
    """
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attention_fc = nn.Linear(hidden_dim, hidden_dim)
        self.context_vector = nn.Parameter(torch.randn(hidden_dim))
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Args:
            x: (batch, seq_len, hidden_dim)
            mask: (batch, seq_len) — 1 for valid, 0 for padding
        
        Returns:
            weighted: (batch, hidden_dim)
        """
        # Attention scores
        u = torch.tanh(self.attention_fc(x))  # (batch, seq_len, hidden_dim)
        scores = torch.matmul(u, self.context_vector)  # (batch, seq_len)
        
        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)
        
        # Softmax
        weights = F.softmax(scores, dim=-1)  # (batch, seq_len)
        
        # Weighted sum
        weighted = torch.bmm(weights.unsqueeze(1), x).squeeze(1)  # (batch, hidden_dim)
        
        return weighted


class HierarchicalAttentionNetwork(nn.Module):
    """
    Hierarchical Attention Networks (HAN) — Yang et al. 2016.
    
    Architecture à 2 niveaux d'attention :
    1. Word-level : attention sur les mots d'une séquence
    2. Sentence-level : attention sur les séquences d'un document
    
    Pour la cybersécurité :
    - Niveau 1 : attention sur les événements d'une session
    - Niveau 2 : attention sur les sessions d'un utilisateur
    
    Référence : Yang et al. "Hierarchical Attention Networks for
                Document Classification" (NAACL 2016)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 64,
        n_classes: int = 10,
        n_words: int = 50,    # Événements par session
        n_sentences: int = 20,  # Sessions par utilisateur
        dropout: float = 0.2,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.n_classes = n_classes
        
        # Word-level encoder (Bi-GRU)
        self.word_gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim // 2,
            num_layers=1,
            bidirectional=True,
            batch_first=True,
        )
        self.word_attention = WordAttention(hidden_dim)
        
        # Sentence-level encoder (Bi-GRU)
        self.sentence_gru = nn.GRU(
            input_size=hidden_dim,
            hidden_size=hidden_dim // 2,
            num_layers=1,
            bidirectional=True,
            batch_first=True,
        )
        self.sentence_attention = WordAttention(hidden_dim)
        
        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, n_classes),
        )
    
    def forward(
        self,
        x: torch.Tensor,
        word_mask: Optional[torch.Tensor] = None,
        sentence_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, n_sentences, n_words, input_dim)
            word_mask: (batch, n_sentences, n_words)
            sentence_mask: (batch, n_sentences)
        
        Returns:
            logits: (batch, n_classes)
        """
        batch_size, n_sent, n_words, _ = x.shape
        
        # Reshape for word-level processing
        x_words = x.view(batch_size * n_sent, n_words, self.input_dim)
        
        # Word-level GRU
        word_out, _ = self.word_gru(x_words)  # (batch*n_sent, n_words, hidden_dim)
        
        # Word-level attention
        if word_mask is not None:
            w_mask = word_mask.view(batch_size * n_sent, n_words)
        else:
            w_mask = None
        
        sentence_vectors = self.word_attention(word_out, w_mask)  # (batch*n_sent, hidden_dim)
        
        # Reshape back
        sentence_vectors = sentence_vectors.view(batch_size, n_sent, self.hidden_dim)
        
        # Sentence-level GRU
        sent_out, _ = self.sentence_gru(sentence_vectors)  # (batch, n_sent, hidden_dim)
        
        # Sentence-level attention
        doc_vectors = self.sentence_attention(sent_out, sentence_mask)  # (batch, hidden_dim)
        
        # Classification
        logits = self.classifier(doc_vectors)  # (batch, n_classes)
        
        return logits


class HANClassifier:
    """Wrapper for Hierarchical Attention Network."""
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 64,
        n_classes: int = 10,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "n_classes": n_classes,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = HierarchicalAttentionNetwork(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            n_classes=n_classes,
        ).to(self.device)
        
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self.criterion = nn.CrossEntropyLoss()
        self._fitted = False
        self._class_names: List[str] = []
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit HAN model."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).long().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            correct = 0
            total = 0
            
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                logits = self.model(batch_X)
                loss = self.criterion(logits, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
                epoch_loss += loss.item()
                _, predicted = logits.max(1)
                total += batch_y.size(0)
                correct += predicted.eq(batch_y).sum().item()
            
            if (epoch + 1) % 10 == 0:
                acc = 100. * correct / total
                logger.info("han_epoch", epoch=epoch + 1, loss=f"{epoch_loss/len(loader):.4f}", acc=f"{acc:.2f}%")
        
        self._fitted = True
        self.model.eval()
        logger.info("han_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray) -> List[ClassificationResult]:
        """Predict with HAN."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            logits = self.model(X_t)
            probs = F.softmax(logits, dim=-1)
        
        results = []
        for i in range(len(X)):
            prob_dist = {str(j): float(probs[i, j]) for j in range(probs.shape[1])}
            pred_class = int(probs[i].argmax())
            confidence = float(probs[i, pred_class])
            
            results.append(ClassificationResult(
                class_id=pred_class,
                class_name=self._class_names[pred_class] if pred_class < len(self._class_names) else str(pred_class),
                probability=confidence,
                confidence=confidence,
                all_probabilities=prob_dist,
                inference_time_ms=(time.time() - start) * 1000 / len(X),
                model_name="HAN",
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 2. PROTOTYPICAL NETWORKS (Few-Shot Learning)
# ═══════════════════════════════════════════════════════════════════════════

class PrototypicalNetwork(nn.Module):
    """
    Prototypical Networks — Few-shot learning.
    
    Apprend un espace de représentation où les points d'une même classe
    sont proches de leur prototype (moyenne des points support).
    
    Pour la cybersécurité :
    - Détection de nouvelles menaces avec très peu d'exemples
    - Adaptation rapide à de nouveaux patterns d'attaque
    - Classification zero-shot / few-shot
    
    Référence : Snell et al. "Prototypical Networks for Few-shot Learning"
                (NeurIPS 2017)
    """
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, n_shot: int = 5):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.n_shot = n_shot
        
        # Encoder network
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input to embedding space."""
        return self.encoder(x)
    
    def compute_prototypes(
        self, support_x: torch.Tensor, support_y: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Compute class prototypes from support set.
        
        Args:
            support_x: (n_support, input_dim)
            support_y: (n_support,) — class labels
        
        Returns:
            prototypes: (n_classes, hidden_dim)
            class_labels: (n_classes,)
        """
        embeddings = self.forward(support_x)
        
        # Get unique classes
        classes = torch.unique(support_y)
        prototypes = []
        
        for c in classes:
            mask = support_y == c
            prototype = embeddings[mask].mean(dim=0)
            prototypes.append(prototype)
        
        return torch.stack(prototypes), classes
    
    def classify(
        self, query_x: torch.Tensor, support_x: torch.Tensor, support_y: torch.Tensor
    ) -> torch.Tensor:
        """
        Classify query points using prototypes.
        
        Args:
            query_x: (n_query, input_dim)
            support_x: (n_support, input_dim)
            support_y: (n_support,)
        
        Returns:
            logits: (n_query, n_classes)
        """
        # Compute prototypes
        prototypes, classes = self.compute_prototypes(support_x, support_y)
        
        # Embed query
        query_embeddings = self.forward(query_x)
        
        # Compute distances to prototypes
        dists = torch.cdist(query_embeddings, prototypes)  # (n_query, n_classes)
        
        # Convert to logits (negative distance)
        logits = -dists
        
        return logits
    
    def loss(
        self, query_x: torch.Tensor, query_y: torch.Tensor,
        support_x: torch.Tensor, support_y: torch.Tensor
    ) -> torch.Tensor:
        """Compute prototypical loss."""
        logits = self.classify(query_x, support_x, support_y)
        return F.cross_entropy(logits, query_y)


class PrototypicalClassifier:
    """Wrapper for Prototypical Networks."""
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 128,
        n_shot: int = 5,
        n_way: int = 5,
        learning_rate: float = 1e-3,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "n_shot": n_shot,
            "n_way": n_way,
            "learning_rate": learning_rate,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = PrototypicalNetwork(input_dim, hidden_dim, n_shot).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self._fitted = False
        
        # Stored support set for inference
        self._support_x: Optional[torch.Tensor] = None
        self._support_y: Optional[torch.Tensor] = None
        self._class_names: List[str] = []
    
    def _create_episode(
        self, X: torch.Tensor, y: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """Create a few-shot episode."""
        classes = torch.unique(y)
        n_classes = min(len(classes), self.params["n_way"])
        selected_classes = classes[torch.randperm(len(classes))[:n_classes]]
        
        support_x = []
        support_y = []
        query_x = []
        query_y = []
        
        for i, c in enumerate(selected_classes):
            mask = y == c
            indices = torch.where(mask)[0]
            perm = indices[torch.randperm(len(indices))]
            
            # Support set
            n_support = min(self.params["n_shot"], len(perm) // 2)
            support_indices = perm[:n_support]
            support_x.append(X[support_indices])
            support_y.append(torch.full((n_support,), i, dtype=torch.long))
            
            # Query set
            query_indices = perm[n_support:]
            if len(query_indices) > 0:
                query_x.append(X[query_indices])
                query_y.append(torch.full((len(query_indices),), i, dtype=torch.long))
        
        return (
            torch.cat(support_x),
            torch.cat(support_y),
            torch.cat(query_x) if query_x else torch.zeros(0, dtype=torch.long),
            torch.cat(query_y) if query_y else torch.zeros(0, dtype=torch.long),
        )
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit Prototypical Network."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).long().to(self.device)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            n_episodes = 20
            
            for _ in range(n_episodes):
                s_x, s_y, q_x, q_y = self._create_episode(X_t, y_t)
                
                if len(q_x) == 0:
                    continue
                
                self.optimizer.zero_grad()
                loss = self.model.loss(q_x, q_y, s_x, s_y)
                loss.backward()
                self.optimizer.step()
                
                epoch_loss += loss.item()
            
            if (epoch + 1) % 10 == 0:
                logger.info("proto_epoch", epoch=epoch + 1, loss=f"{epoch_loss/n_episodes:.4f}")
        
        self._fitted = True
        self.model.eval()
        
        # Store all data as support set
        self._support_x = X_t
        self._support_y = y_t
        
        logger.info("prototypical_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray) -> List[ClassificationResult]:
        """Predict with Prototypical Network."""
        import time
        start = time.time()
        
        if self._support_x is None:
            return [ClassificationResult(0, "unknown", 0.0, 0.0, model_name="Prototypical")]
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            logits = self.model.classify(X_t, self._support_x, self._support_y)
            probs = F.softmax(logits, dim=-1)
        
        results = []
        for i in range(len(X)):
            prob_dist = {str(j): float(probs[i, j]) for j in range(probs.shape[1])}
            pred_class = int(probs[i].argmax())
            confidence = float(probs[i, pred_class])
            
            results.append(ClassificationResult(
                class_id=pred_class,
                class_name=self._class_names[pred_class] if pred_class < len(self._class_names) else str(pred_class),
                probability=confidence,
                confidence=confidence,
                all_probabilities=prob_dist,
                inference_time_ms=(time.time() - start) * 1000 / len(X),
                model_name="Prototypical",
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 3. SET TRANSFORMERS
# ═══════════════════════════════════════════════════════════════════════════

class SetAttentionBlock(nn.Module):
    """
    Set Attention Block (SAB) — Set Transformer.
    
    MAB(X, Y) = LayerNorm(H + rFF(H)) où H = LayerNorm(X + Multihead(X, Y, Y))
    SAB(X) = MAB(X, X)
    """
    
    def __init__(self, d_model: int, n_heads: int, dropout: float = 0.1):
        super().__init__()
        self.multihead = nn.MultiheadAttention(d_model, n_heads, dropout=dropout, batch_first=True)
        self.ff = nn.Sequential(
            nn.Linear(d_model, d_model * 4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model * 4, d_model),
        )
        self.ln1 = nn.LayerNorm(d_model)
        self.ln2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """SAB forward."""
        # Self-attention
        attn_out, _ = self.multihead(x, x, x)
        x = self.ln1(x + self.dropout(attn_out))
        
        # Feed-forward
        ff_out = self.ff(x)
        x = self.ln2(x + self.dropout(ff_out))
        
        return x


class PoolingMultiheadAttention(nn.Module):
    """
    Pooling Multihead Attention (PMA) — Set Transformer.
    
    PMA_k(Z) = MAB(S, rFF(Z)) où S sont des vecteurs de pooling learnables.
    Réduit un ensemble de taille n à k éléments.
    """
    
    def __init__(self, d_model: int, n_heads: int, k: int, dropout: float = 0.1):
        super().__init__()
        self.seed_vectors = nn.Parameter(torch.randn(1, k, d_model))
        self.mab = SetAttentionBlock(d_model, n_heads, dropout)
    
    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """PMA forward."""
        batch_size = z.size(0)
        seeds = self.seed_vectors.expand(batch_size, -1, -1)
        return self.mab(seeds)


class SetTransformer(nn.Module):
    """
    Set Transformer — Lee et al. 2019.
    
    Architecture pour traiter des ensembles non ordonnés :
    - Invariant aux permutations (indispensable pour IPs, events)
    - Peut traiter des ensembles de taille variable
    - Attention pooling pour résumer l'ensemble
    
    Pour la cybersécurité :
    - Classification d'ensembles d'alertes
    - Analyse de flux réseau (paquets non ordonnés)
    - Agrégation d'indicateurs de compromission
    
    Référence : Lee et al. "Set Transformer: A Framework for
                Attention-based Permutation-Invariant Neural Networks" (ICML 2019)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        d_model: int = 128,
        n_heads: int = 4,
        n_blocks: int = 2,
        n_classes: int = 10,
        k_pool: int = 1,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, d_model)
        
        # Set Attention Blocks (encoder)
        self.encoder_blocks = nn.ModuleList([
            SetAttentionBlock(d_model, n_heads, dropout)
            for _ in range(n_blocks)
        ])
        
        # Pooling
        self.pooling = PoolingMultiheadAttention(d_model, n_heads, k_pool, dropout)
        
        # Decoder blocks
        self.decoder_blocks = nn.ModuleList([
            SetAttentionBlock(d_model, n_heads, dropout)
            for _ in range(n_blocks)
        ])
        
        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, n_classes),
        )
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, n_elements, input_dim)
            mask: (batch, n_elements) — 1 for valid, 0 for padding
        
        Returns:
            logits: (batch, n_classes)
        """
        batch_size, n_elements, _ = x.shape
        
        # Input projection
        h = self.input_proj(x)  # (batch, n_elements, d_model)
        
        # Apply mask
        if mask is not None:
            h = h * mask.unsqueeze(-1)
        
        # Encoder blocks
        for block in self.encoder_blocks:
            h = block(h)
        
        # Pooling
        pooled = self.pooling(h)  # (batch, k_pool, d_model)
        
        # Decoder blocks
        for block in self.decoder_blocks:
            pooled = block(pooled)
        
        # Global pooling (mean over k_pool)
        pooled = pooled.mean(dim=1)  # (batch, d_model)
        
        # Classification
        logits = self.classifier(pooled)  # (batch, n_classes)
        
        return logits


class SetTransformerClassifier:
    """Wrapper for Set Transformer."""
    
    def __init__(
        self,
        input_dim: int = 128,
        d_model: int = 128,
        n_heads: int = 4,
        n_classes: int = 10,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "d_model": d_model,
            "n_heads": n_heads,
            "n_classes": n_classes,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = SetTransformer(
            input_dim=input_dim,
            d_model=d_model,
            n_heads=n_heads,
            n_classes=n_classes,
        ).to(self.device)
        
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self.criterion = nn.CrossEntropyLoss()
        self._fitted = False
        self._class_names: List[str] = []
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit Set Transformer."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).long().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            correct = 0
            total = 0
            
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                logits = self.model(batch_X)
                loss = self.criterion(logits, batch_y)
                loss.backward()
                self.optimizer.step()
                
                epoch_loss += loss.item()
                _, predicted = logits.max(1)
                total += batch_y.size(0)
                correct += predicted.eq(batch_y).sum().item()
            
            if (epoch + 1) % 10 == 0:
                acc = 100. * correct / total
                logger.info("set_transformer_epoch", epoch=epoch + 1, loss=f"{epoch_loss/len(loader):.4f}", acc=f"{acc:.2f}%")
        
        self._fitted = True
        self.model.eval()
        logger.info("set_transformer_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray) -> List[ClassificationResult]:
        """Predict with Set Transformer."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            logits = self.model(X_t)
            probs = F.softmax(logits, dim=-1)
        
        results = []
        for i in range(len(X)):
            prob_dist = {str(j): float(probs[i, j]) for j in range(probs.shape[1])}
            pred_class = int(probs[i].argmax())
            confidence = float(probs[i, pred_class])
            
            results.append(ClassificationResult(
                class_id=pred_class,
                class_name=self._class_names[pred_class] if pred_class < len(self._class_names) else str(pred_class),
                probability=confidence,
                confidence=confidence,
                all_probabilities=prob_dist,
                inference_time_ms=(time.time() - start) * 1000 / len(X),
                model_name="SetTransformer",
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 4. PERCEIVER IO — DeepMind
# ═══════════════════════════════════════════════════════════════════════════

class PerceiverIO(nn.Module):
    """
    Perceiver IO — DeepMind, 2021.
    
    Architecture générique qui peut traiter n'importe quel type d'entrée
    (images, audio, texte, points, ensembles) en utilisant un espace latent
    de taille fixe avec attention cross-attention.
    
    Avantages :
    - Complexité linéaire en taille d'entrée (pas quadratique)
    - Peut traiter des entrées de taille arbitraire
    - Architecture unique pour tous les types de données
    
    Référence : Jaegle et al. "Perceiver IO: A General Architecture for
                Structured Inputs & Outputs" (DeepMind, ICLR 2022)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        latent_dim: int = 256,
        n_latents: int = 32,
        n_heads: int = 8,
        n_layers: int = 6,
        n_classes: int = 10,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.n_latents = n_latents
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, latent_dim)
        
        # Learnable latent array
        self.latent = nn.Parameter(torch.randn(1, n_latents, latent_dim) * 0.02)
        
        # Cross-attention + Transformer layers
        self.layers = nn.ModuleList()
        for _ in range(n_layers):
            layer = nn.ModuleDict({
                # Cross-attention: latent attends to input
                "cross_attn": nn.MultiheadAttention(latent_dim, n_heads, dropout=dropout, batch_first=True),
                "cross_ln": nn.LayerNorm(latent_dim),
                # Self-attention: latent attends to itself
                "self_attn": nn.MultiheadAttention(latent_dim, n_heads, dropout=dropout, batch_first=True),
                "self_ln1": nn.LayerNorm(latent_dim),
                # Feed-forward
                "ff": nn.Sequential(
                    nn.Linear(latent_dim, latent_dim * 4),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(latent_dim * 4, latent_dim),
                ),
                "self_ln2": nn.LayerNorm(latent_dim),
                "dropout": nn.Dropout(dropout),
            })
            self.layers.append(layer)
        
        # Output projection
        self.output_proj = nn.Sequential(
            nn.Linear(latent_dim, latent_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(latent_dim, n_classes),
        )
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: (batch, n_inputs, input_dim)
            mask: (batch, n_inputs)
        
        Returns:
            logits: (batch, n_classes)
        """
        batch_size = x.size(0)
        
        # Project input
        x_proj = self.input_proj(x)  # (batch, n_inputs, latent_dim)
        
        # Expand latent
        latent = self.latent.expand(batch_size, -1, -1)  # (batch, n_latents, latent_dim)
        
        # Process through layers
        for layer in self.layers:
            # Cross-attention: latent -> input
            attn_out, _ = layer["cross_attn"](latent, x_proj, x_proj, key_padding_mask=mask)
            latent = layer["cross_ln"](latent + layer["dropout"](attn_out))
            
            # Self-attention
            attn_out, _ = layer["self_attn"](latent, latent, latent)
            latent = layer["self_ln1"](latent + layer["dropout"](attn_out))
            
            # Feed-forward
            ff_out = layer["ff"](latent)
            latent = layer["self_ln2"](latent + layer["dropout"](ff_out))
        
        # Global pooling
        pooled = latent.mean(dim=1)  # (batch, latent_dim)
        
        # Classification
        logits = self.output_proj(pooled)  # (batch, n_classes)
        
        return logits


class PerceiverIOClassifier:
    """Wrapper for Perceiver IO."""
    
    def __init__(
        self,
        input_dim: int = 128,
        latent_dim: int = 256,
        n_latents: int = 32,
        n_classes: int = 10,
        learning_rate: float = 1e-3,
        batch_size: int = 32,
        n_epochs: int = 50,
        device: str = "cpu",
    ):
        self.params = {
            "input_dim": input_dim,
            "latent_dim": latent_dim,
            "n_latents": n_latents,
            "n_classes": n_classes,
            "learning_rate": learning_rate,
            "batch_size": batch_size,
            "n_epochs": n_epochs,
        }
        
        self.device = torch.device(device)
        self.model = PerceiverIO(
            input_dim=input_dim,
            latent_dim=latent_dim,
            n_latents=n_latents,
            n_classes=n_classes,
        ).to(self.device)
        
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        self.criterion = nn.CrossEntropyLoss()
        self._fitted = False
        self._class_names: List[str] = []
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Fit Perceiver IO."""
        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).long().to(self.device)
        
        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.params["batch_size"], shuffle=True)
        
        self.model.train()
        for epoch in range(self.params["n_epochs"]):
            epoch_loss = 0.0
            correct = 0
            total = 0
            
            for batch_X, batch_y in loader:
                self.optimizer.zero_grad()
                logits = self.model(batch_X)
                loss = self.criterion(logits, batch_y)
                loss.backward()
                self.optimizer.step()
                
                epoch_loss += loss.item()
                _, predicted = logits.max(1)
                total += batch_y.size(0)
                correct += predicted.eq(batch_y).sum().item()
            
            if (epoch + 1) % 10 == 0:
                acc = 100. * correct / total
                logger.info("perceiver_epoch", epoch=epoch + 1, loss=f"{epoch_loss/len(loader):.4f}", acc=f"{acc:.2f}%")
        
        self._fitted = True
        self.model.eval()
        logger.info("perceiver_trained", epochs=self.params["n_epochs"])
    
    def predict(self, X: np.ndarray) -> List[ClassificationResult]:
        """Predict with Perceiver IO."""
        import time
        start = time.time()
        
        X_t = torch.from_numpy(X).float().to(self.device)
        
        with torch.no_grad():
            logits = self.model(X_t)
            probs = F.softmax(logits, dim=-1)
        
        results = []
        for i in range(len(X)):
            prob_dist = {str(j): float(probs[i, j]) for j in range(probs.shape[1])}
            pred_class = int(probs[i].argmax())
            confidence = float(probs[i, pred_class])
            
            results.append(ClassificationResult(
                class_id=pred_class,
                class_name=self._class_names[pred_class] if pred_class < len(self._class_names) else str(pred_class),
                probability=confidence,
                confidence=confidence,
                all_probabilities=prob_dist,
                inference_time_ms=(time.time() - start) * 1000 / len(X),
                model_name="PerceiverIO",
            ))
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_ultra_classifier(
    input_dim: int = 128,
    hidden_dim: int = 64,
    n_classes: int = 10,
    device: str = "cpu",
    use_han: bool = True,
    use_prototypical: bool = True,
    use_set_transformer: bool = True,
    use_perceiver: bool = True,
) -> Dict[str, Any]:
    """
    Crée le système de classification complet Niveau 3.
    
    Retourne un dict avec tous les classifieurs.
    """
    classifiers = {}
    
    if use_han:
        classifiers["han"] = HANClassifier(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            n_classes=n_classes,
            device=device,
        )
        logger.info("✅ HAN (Hierarchical Attention Network) initialized")
    
    if use_prototypical:
        classifiers["prototypical"] = PrototypicalClassifier(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            device=device,
        )
        logger.info("✅ Prototypical Network initialized")
    
    if use_set_transformer:
        classifiers["set_transformer"] = SetTransformerClassifier(
            input_dim=input_dim,
            d_model=hidden_dim,
            n_classes=n_classes,
            device=device,
        )
        logger.info("✅ Set Transformer initialized")
    
    if use_perceiver:
        classifiers["perceiver"] = PerceiverIOClassifier(
            input_dim=input_dim,
            latent_dim=hidden_dim * 2,
            n_classes=n_classes,
            device=device,
        )
        logger.info("✅ Perceiver IO initialized")
    
    return {
        "classifiers": classifiers,
        "config": {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "n_classes": n_classes,
            "device": device,
            "n_classifiers": len(classifiers),
        },
    }


def create_ultra_classifier_minimal() -> Dict[str, Any]:
    """Version minimale pour démarrage rapide."""
    return create_ultra_classifier(
        input_dim=128,
        hidden_dim=64,
        n_classes=10,
        use_han=True,
        use_prototypical=False,
        use_set_transformer=False,
        use_perceiver=False,
    )


def create_ultra_classifier_full() -> Dict[str, Any]:
    """Version complète avec tous les classifieurs."""
    return create_ultra_classifier(
        input_dim=128,
        hidden_dim=64,
        n_classes=10,
        use_han=True,
        use_prototypical=True,
        use_set_transformer=True,
        use_perceiver=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# CLASSIFICATION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

class UltraClassifierPipeline:
    """
    Pipeline complet qui intègre tous les classifieurs.
    
    Coordonne :
    - HAN (Hierarchical Attention Networks)
    - Prototypical Networks (Few-shot Learning)
    - Set Transformers (Permutation Invariant)
    - Perceiver IO (DeepMind Generic Architecture)
    - Ensemble des classifications
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 64,
        n_classes: int = 10,
        device: str = "cpu",
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.n_classes = n_classes
        self.device = device
        
        self.classifier_system = create_ultra_classifier_full()
        
        # Performance tracking
        self._performance: Dict[str, List[float]] = {
            name: [] for name in self.classifier_system["classifiers"]
        }
        
        logger.info("🚀 UltraClassifierPipeline initialized")
    
    def fit_all(self, X: np.ndarray, y: np.ndarray):
        """Fit all classifiers on training data."""
        for name, classifier in self.classifier_system["classifiers"].items():
            try:
                classifier.fit(X, y)
                logger.info(f"✅ {name} fitted")
            except Exception as e:
                logger.error(f"Failed to fit {name}", error=str(e))
    
    def predict_all(self, X: np.ndarray) -> Dict[str, List[ClassificationResult]]:
        """Predict with all classifiers."""
        results = {}
        for name, classifier in self.classifier_system["classifiers"].items():
            try:
                results[name] = classifier.predict(X)
            except Exception as e:
                logger.error(f"Failed to predict with {name}", error=str(e))
                results[name] = []
        return results
    
    def predict_ensemble(self, X: np.ndarray) -> List[ClassificationResult]:
        """
        Classification ensembliste : vote pondéré de tous les classifieurs.
        """
        all_results = self.predict_all(X)
        
        if not all_results:
            return []
        
        n_samples = len(X)
        ensemble_results = []
        
        for i in range(n_samples):
            class_votes: Dict[int, float] = {}
            class_names: Dict[int, str] = {}
            
            for name, results in all_results.items():
                if i < len(results):
                    r = results[i]
                    class_votes[r.class_id] = class_votes.get(r.class_id, 0.0) + r.confidence
                    class_names[r.class_id] = r.class_name
            
            if class_votes:
                best_class = max(class_votes, key=class_votes.get)
                total_votes = sum(class_votes.values())
                
                ensemble_results.append(ClassificationResult(
                    class_id=best_class,
                    class_name=class_names.get(best_class, str(best_class)),
                    probability=class_votes[best_class] / total_votes if total_votes > 0 else 0.0,
                    confidence=class_votes[best_class] / len(all_results),
                    all_probabilities={str(k): v / total_votes for k, v in class_votes.items()},
                    inference_time_ms=0.0,
                    model_name="Ensemble",
                ))
        
        return ensemble_results
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get complete system statistics."""
        return {
            "classifiers": list(self.classifier_system["classifiers"].keys()),
            "config": self.classifier_system["config"],
            "n_classifiers": len(self.classifier_system["classifiers"]),
        }


# Instance globale
ultra_classifier_pipeline = UltraClassifierPipeline()


def get_ultra_classifier() -> UltraClassifierPipeline:
    """Get the global ultra classifier instance."""
    return ultra_classifier_pipeline


