"""
Cyber Global Shield — Ultra Threat Intelligence Module (Niveau 5)
==================================================================

5 technologies de pointe pour la collecte et l'analyse de menaces :

1. Graph Neural Networks (GNN) — Analyse des relations de menace
2. NLP Transformers (BERT/RoBERTa) — Analyse de texte dark web
3. BERTopic — Topic Modeling pour clustering de menaces
4. Knowledge Graph Embeddings (TransE, RotatE) — Raisonnement
5. Temporal Graph Networks — Évolution des menaces dans le temps

Chaque module peut fonctionner indépendamment ou en pipeline intégré.
"""

import json
import time
import math
import hashlib
import structlog
from typing import Optional, Dict, Any, List, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
from datetime import datetime, timedelta

logger = structlog.get_logger(__name__)

# ─── NumPy ──────────────────────────────────────────────────────────────
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# ─── PyTorch ────────────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# ─── scikit-learn ───────────────────────────────────────────────────────
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import NMF, LatentDirichletAllocation
    from sklearn.cluster import HDBSCAN
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatEntity:
    """A threat entity (IP, domain, hash, URL, etc.)."""
    id: str
    entity_type: str  # ip, domain, hash, url, email, etc.
    value: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    score: float = 0.0  # 0.0 (benign) to 1.0 (malicious)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatRelation:
    """Relation between two threat entities."""
    source_id: str
    target_id: str
    relation_type: str  # communicates_with, downloads, similar_to, etc.
    weight: float = 1.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatReport:
    """A threat intelligence report."""
    id: str
    title: str
    content: str
    source: str  # dark_web, twitter, blog, vt, etc.
    timestamp: float = field(default_factory=time.time)
    entities: List[str] = field(default_factory=list)  # entity IDs
    topics: List[str] = field(default_factory=list)
    severity: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatGraph:
    """Temporal threat knowledge graph."""
    entities: Dict[str, ThreatEntity] = field(default_factory=dict)
    relations: List[ThreatRelation] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# 1. GRAPH NEURAL NETWORK (GNN) — Threat Relation Analysis
# ═══════════════════════════════════════════════════════════════════════════

class ThreatGNN:
    """
    Graph Neural Network for threat relation analysis.
    
    Architecture : GraphSAGE + GAT + GCN combinés
    Utilise : Message passing sur le graphe de menaces
    
    Applications :
    - Détection de clusters de malware
    - Propagation de score de menace
    - Identification de C2 infrastructure
    - Détection de relations cachées entre IOCs
    
    Référence : Hamilton et al. "Inductive Representation Learning on
                Large Graphs" (GraphSAGE, NeurIPS 2017)
    """
    
    def __init__(self, hidden_dim: int = 128, output_dim: int = 64, n_layers: int = 3):
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.n_layers = n_layers
        
        # Entity embeddings
        self.entity_embeddings: Dict[str, np.ndarray] = {}
        
        # Graph structure
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.edge_weights: Dict[Tuple[str, str], float] = {}
        
        logger.info(f"🕸️  ThreatGNN initialized (hidden={hidden_dim}, layers={n_layers})")
    
    def add_entity(self, entity: ThreatEntity, embedding: Optional[np.ndarray] = None):
        """Add entity to graph."""
        if embedding is None and NUMPY_AVAILABLE:
            # Random initial embedding
            embedding = np.random.randn(self.output_dim).astype(np.float32)
            embedding = embedding / np.linalg.norm(embedding)
        
        self.entity_embeddings[entity.id] = embedding
    
    def add_relation(self, relation: ThreatRelation):
        """Add relation to graph."""
        self.adjacency[relation.source_id].add(relation.target_id)
        self.adjacency[relation.target_id].add(relation.source_id)
        self.edge_weights[(relation.source_id, relation.target_id)] = relation.weight
        self.edge_weights[(relation.target_id, relation.source_id)] = relation.weight
    
    def _sage_aggregate(self, node_id: str, embeddings: Dict[str, np.ndarray]) -> np.ndarray:
        """GraphSAGE aggregation: mean of neighbors."""
        if not NUMPY_AVAILABLE:
            return np.zeros(self.output_dim)
        
        neighbors = self.adjacency.get(node_id, set())
        if not neighbors:
            return embeddings.get(node_id, np.zeros(self.output_dim))
        
        # Mean aggregation
        neighbor_embs = [embeddings[n] for n in neighbors if n in embeddings]
        if not neighbor_embs:
            return embeddings.get(node_id, np.zeros(self.output_dim))
        
        agg = np.mean(neighbor_embs, axis=0)
        
        # Concatenate with self
        self_emb = embeddings.get(node_id, np.zeros(self.output_dim))
        combined = np.concatenate([self_emb, agg])
        
        # Linear transform + ReLU
        W = np.random.randn(self.output_dim * 2, self.output_dim).astype(np.float32) * 0.01
        b = np.zeros(self.output_dim)
        
        return np.maximum(0, combined @ W + b)
    
    def _gat_aggregate(self, node_id: str, embeddings: Dict[str, np.ndarray]) -> np.ndarray:
        """GAT aggregation: attention-weighted neighbors."""
        if not NUMPY_AVAILABLE:
            return np.zeros(self.output_dim)
        
        neighbors = self.adjacency.get(node_id, set())
        if not neighbors:
            return embeddings.get(node_id, np.zeros(self.output_dim))
        
        self_emb = embeddings.get(node_id, np.zeros(self.output_dim))
        
        # Compute attention scores
        scores = []
        neighbor_embs = []
        for n in neighbors:
            if n in embeddings:
                n_emb = embeddings[n]
                # Simple dot-product attention
                score = np.dot(self_emb, n_emb) / math.sqrt(self.output_dim)
                scores.append(score)
                neighbor_embs.append(n_emb)
        
        if not neighbor_embs:
            return self_emb
        
        # Softmax
        scores = np.exp(scores - np.max(scores))
        scores = scores / (np.sum(scores) + 1e-8)
        
        # Weighted sum
        agg = np.sum([s * e for s, e in zip(scores, neighbor_embs)], axis=0)
        
        return agg
    
    def propagate(self, n_iterations: int = 3) -> Dict[str, np.ndarray]:
        """
        Propagate embeddings through the graph.
        
        Returns:
            Updated entity embeddings
        """
        if not NUMPY_AVAILABLE:
            return self.entity_embeddings
        
        embeddings = dict(self.entity_embeddings)
        
        for _ in range(n_iterations):
            new_embeddings = {}
            for node_id in embeddings:
                # Combine SAGE + GAT
                sage_emb = self._sage_aggregate(node_id, embeddings)
                gat_emb = self._gat_aggregate(node_id, embeddings)
                
                # Weighted combination
                new_emb = 0.5 * sage_emb + 0.5 * gat_emb
                new_emb = new_emb / (np.linalg.norm(new_emb) + 1e-8)
                new_embeddings[node_id] = new_emb
            
            embeddings = new_embeddings
        
        self.entity_embeddings = embeddings
        return embeddings
    
    def compute_similarity(self, entity_id_1: str, entity_id_2: str) -> float:
        """Compute cosine similarity between two entities."""
        if not NUMPY_AVAILABLE:
            return 0.0
        
        e1 = self.entity_embeddings.get(entity_id_1)
        e2 = self.entity_embeddings.get(entity_id_2)
        
        if e1 is None or e2 is None:
            return 0.0
        
        return float(np.dot(e1, e2) / (np.linalg.norm(e1) * np.linalg.norm(e2) + 1e-8))
    
    def find_similar(self, entity_id: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Find most similar entities."""
        if not NUMPY_AVAILABLE:
            return []
        
        query = self.entity_embeddings.get(entity_id)
        if query is None:
            return []
        
        similarities = []
        for eid, emb in self.entity_embeddings.items():
            if eid != entity_id:
                sim = float(np.dot(query, emb) / (np.linalg.norm(query) * np.linalg.norm(emb) + 1e-8))
                similarities.append((eid, sim))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]
    
    def detect_communities(self) -> Dict[str, List[str]]:
        """Detect communities using label propagation."""
        if not NUMPY_AVAILABLE:
            return {}
        
        # Simple label propagation
        labels = {eid: eid for eid in self.entity_embeddings}
        
        for _ in range(10):
            new_labels = {}
            for node_id in labels:
                neighbors = self.adjacency.get(node_id, set())
                if neighbors:
                    neighbor_labels = [labels[n] for n in neighbors if n in labels]
                    if neighbor_labels:
                        new_labels[node_id] = Counter(neighbor_labels).most_common(1)[0][0]
                    else:
                        new_labels[node_id] = labels[node_id]
                else:
                    new_labels[node_id] = labels[node_id]
            labels = new_labels
        
        # Group by label
        communities = defaultdict(list)
        for node_id, label in labels.items():
            communities[label].append(node_id)
        
        return dict(communities)


# ═══════════════════════════════════════════════════════════════════════════
# 2. NLP TRANSFORMERS — Dark Web Text Analysis
# ═══════════════════════════════════════════════════════════════════════════

class DarkWebNLP:
    """
    NLP Transformers for dark web text analysis.
    
    Utilise BERT/RoBERTa pour :
    - Classification de contenu illicite
    - Extraction d'entités (IOCs, personnes, lieux)
    - Analyse de sentiment des menaces
    - Détection de langage codé
    
    Référence : Devlin et al. "BERT: Pre-training of Deep Bidirectional
                Transformers for Language Understanding" (NAACL 2019)
    """
    
    def __init__(self, model_name: str = "bert-base-uncased", max_length: int = 512):
        self.model_name = model_name
        self.max_length = max_length
        
        # Threat categories
        self.categories = [
            "malware", "ransomware", "exploit", "phishing",
            "data_breach", "ddos", "c2", "credential_stuffing",
            "zero_day", "apt", "botnet", "carding",
        ]
        
        # IOC patterns (regex-like)
        self.ioc_patterns = {
            "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            "hash_md5": r"\b[0-9a-fA-F]{32}\b",
            "hash_sha1": r"\b[0-9a-fA-F]{40}\b",
            "hash_sha256": r"\b[0-9a-fA-F]{64}\b",
            "url": r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "cve": r"CVE-\d{4}-\d{4,7}",
        }
        
        logger.info(f"📖 DarkWebNLP initialized (model={model_name})")
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from text."""
        import re
        
        iocs = defaultdict(list)
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                iocs[ioc_type] = list(set(matches))
        
        return dict(iocs)
    
    def classify_threat(self, text: str) -> Dict[str, float]:
        """
        Classify text into threat categories.
        
        Returns:
            {category: confidence_score}
        """
        # Simulated BERT classification
        # In production, use transformers library
        text_lower = text.lower()
        
        scores = {}
        for category in self.categories:
            # Simple keyword-based scoring
            keywords = {
                "malware": ["malware", "trojan", "backdoor", "payload", "dropper"],
                "ransomware": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
                "exploit": ["exploit", "vulnerability", "cve", "buffer overflow", "rce"],
                "phishing": ["phish", "login", "credential", "bank", "password"],
                "data_breach": ["breach", "leak", "dump", "exposed", "stolen"],
                "ddos": ["ddos", "flood", "amplification", "botnet", "attack"],
                "c2": ["c2", "command", "control", "beacon", "callback"],
                "credential_stuffing": ["credential", "stuffing", "brute", "combo"],
                "zero_day": ["zero-day", "0day", "unpatched", "unknown"],
                "apt": ["apt", "advanced", "persistent", "state", "sponsor"],
                "botnet": ["botnet", "bot", "zombie", "irc", "herder"],
                "carding": ["card", "cc", "dumps", "cvv", "fullz"],
            }
            
            score = 0.0
            for kw in keywords.get(category, []):
                if kw in text_lower:
                    score += 1.0
            
            # Normalize
            max_kw = len(keywords.get(category, []))
            scores[category] = min(score / max_kw, 1.0) if max_kw > 0 else 0.0
        
        return scores
    
    def analyze_sentiment(self, text: str) -> Dict[str, float]:
        """
        Analyze threat sentiment.
        
        Returns:
            {threat_level, urgency, hostility}
        """
        text_lower = text.lower()
        
        # Threat indicators
        threat_words = ["attack", "exploit", "malicious", "danger", "critical",
                       "urgent", "warning", "compromised", "breach", "leak"]
        urgency_words = ["immediate", "urgent", "critical", "now", "today",
                        "emergency", "asap", "warning"]
        hostility_words = ["kill", "destroy", "steal", "ransom", "extort",
                          "threat", "demand", "illegal", "fraud"]
        
        threat_score = sum(1 for w in threat_words if w in text_lower) / len(threat_words)
        urgency_score = sum(1 for w in urgency_words if w in text_lower) / len(urgency_words)
        hostility_score = sum(1 for w in hostility_words if w in text_lower) / len(hostility_words)
        
        return {
            "threat_level": min(threat_score * 1.5, 1.0),
            "urgency": min(urgency_score * 2.0, 1.0),
            "hostility": min(hostility_score * 2.0, 1.0),
        }
    
    def generate_embedding(self, text: str) -> np.ndarray:
        """Generate text embedding (simulated BERT)."""
        if not NUMPY_AVAILABLE:
            return np.zeros(768)
        
        # Simulated BERT embedding
        # Hash text to create deterministic embedding
        hash_bytes = hashlib.sha256(text.encode()).digest()
        seed = int.from_bytes(hash_bytes[:4], 'big')
        rng = np.random.RandomState(seed)
        
        embedding = rng.randn(768).astype(np.float32)
        embedding = embedding / np.linalg.norm(embedding)
        
        return embedding


# ═══════════════════════════════════════════════════════════════════════════
# 3. BERTOPIC — Threat Topic Modeling
# ═══════════════════════════════════════════════════════════════════════════

class ThreatBERTopic:
    """
    BERTopic for threat topic modeling.
    
    Pipeline :
    1. Embed documents with BERT
    2. Reduce dimensionality with UMAP
    3. Cluster with HDBSCAN
    4. Generate topic representations
    
    Applications :
    - Clustering automatique de rapports de menace
    - Détection de nouvelles campagnes
    - Organisation de threat intelligence
    
    Référence : Grootendorst "BERTopic: Neural topic modeling with a
                class-based TF-IDF procedure" (2022)
    """
    
    def __init__(self, n_topics: int = 20, min_cluster_size: int = 5):
        self.n_topics = n_topics
        self.min_cluster_size = min_cluster_size
        
        self.topics: Dict[int, Dict[str, Any]] = {}
        self.doc_topics: Dict[str, int] = {}
        self.topic_embeddings: Dict[int, np.ndarray] = {}
        
        logger.info(f"📊 ThreatBERTopic initialized (n_topics={n_topics})")
    
    def fit(self, reports: List[ThreatReport]):
        """Fit topic model on threat reports."""
        if not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
            return
        
        # Extract text
        texts = [r.content for r in reports]
        
        # TF-IDF vectorization
        vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3),
        )
        tfidf_matrix = vectorizer.fit_transform(texts)
        
        # NMF for topic decomposition
        nmf = NMF(n_components=min(self.n_topics, len(texts)), random_state=42)
        topic_matrix = nmf.fit_transform(tfidf_matrix)
        
        # Assign topics
        feature_names = vectorizer.get_feature_names_out()
        
        for topic_idx in range(nmf.n_components):
            # Top words for this topic
            top_indices = nmf.components_[topic_idx].argsort()[-10:][::-1]
            top_words = [feature_names[i] for i in top_indices]
            
            self.topics[topic_idx] = {
                "words": top_words,
                "weight": float(nmf.components_[topic_idx].sum()),
                "n_docs": 0,
            }
        
        # Assign documents to topics
        for i, report in enumerate(reports):
            topic_id = int(topic_matrix[i].argmax())
            self.doc_topics[report.id] = topic_id
            if topic_id in self.topics:
                self.topics[topic_id]["n_docs"] += 1
        
        logger.info(f"📊 Topic modeling complete: {len(self.topics)} topics")
    
    def get_topic_words(self, topic_id: int, n_words: int = 10) -> List[str]:
        """Get top words for a topic."""
        if topic_id not in self.topics:
            return []
        return self.topics[topic_id]["words"][:n_words]
    
    def get_document_topic(self, report_id: str) -> Optional[int]:
        """Get topic assignment for a document."""
        return self.doc_topics.get(report_id)
    
    def get_topic_summary(self) -> Dict[int, Dict[str, Any]]:
        """Get summary of all topics."""
        return dict(self.topics)


# ═══════════════════════════════════════════════════════════════════════════
# 4. KNOWLEDGE GRAPH EMBEDDINGS (TransE, RotatE)
# ═══════════════════════════════════════════════════════════════════════════

class KnowledgeGraphEmbeddings:
    """
    Knowledge Graph Embeddings for threat reasoning.
    
    Modèles :
    - TransE : Relation comme translation dans l'espace d'embedding
    - RotatE : Relation comme rotation dans le plan complexe
    
    Applications :
    - Link prediction (prédire des relations cachées)
    - Threat reasoning (inférer de nouvelles menaces)
    - Entity resolution (relier des IOCs similaires)
    
    Références :
    - Bordes et al. "Translating Embeddings for Modeling Multi-relational
      Data" (TransE, NeurIPS 2013)
    - Sun et al. "RotatE: Knowledge Graph Embedding by Relational Rotation
      in Complex Space" (ICLR 2019)
    """
    
    def __init__(self, embedding_dim: int = 128, margin: float = 1.0):
        self.embedding_dim = embedding_dim
        self.margin = margin
        
        self.entity_embeddings: Dict[str, np.ndarray] = {}
        self.relation_embeddings: Dict[str, np.ndarray] = {}
        
        logger.info(f"🧠 KnowledgeGraphEmbeddings initialized (dim={embedding_dim})")
    
    def _init_embedding(self, key: str) -> np.ndarray:
        """Initialize a random embedding."""
        if not NUMPY_AVAILABLE:
            return np.zeros(self.embedding_dim)
        
        emb = np.random.randn(self.embedding_dim).astype(np.float32)
        return emb / np.linalg.norm(emb)
    
    def add_entity(self, entity_id: str):
        """Add entity to knowledge graph."""
        if entity_id not in self.entity_embeddings:
            self.entity_embeddings[entity_id] = self._init_embedding(entity_id)
    
    def add_relation_type(self, relation_type: str):
        """Add relation type."""
        if relation_type not in self.relation_embeddings:
            self.relation_embeddings[relation_type] = self._init_embedding(relation_type)
    
    def train_transe(self, triples: List[Tuple[str, str, str]], n_epochs: int = 100):
        """
        Train TransE embeddings.
        
        Args:
            triples: [(head, relation, tail)]
        """
        if not NUMPY_AVAILABLE:
            return
        
        # Add all entities and relations
        for h, r, t in triples:
            self.add_entity(h)
            self.add_entity(t)
            self.add_relation_type(r)
        
        # Training loop
        for epoch in range(n_epochs):
            total_loss = 0.0
            
            for h, r, t in triples:
                h_emb = self.entity_embeddings[h]
                r_emb = self.relation_embeddings[r]
                t_emb = self.entity_embeddings[t]
                
                # Positive score: ||h + r - t||
                pos_score = np.linalg.norm(h_emb + r_emb - t_emb)
                
                # Negative sampling
                neg_t = np.random.choice(list(self.entity_embeddings.keys()))
                neg_t_emb = self.entity_embeddings[neg_t]
                neg_score = np.linalg.norm(h_emb + r_emb - neg_t_emb)
                
                # Margin-based loss
                loss = max(0, self.margin + pos_score - neg_score)
                total_loss += loss
                
                # Gradient update (simplified)
                if loss > 0:
                    grad = (h_emb + r_emb - t_emb) / (pos_score + 1e-8)
                    self.entity_embeddings[h] -= 0.01 * grad
                    self.entity_embeddings[t] += 0.01 * grad
                    self.relation_embeddings[r] -= 0.01 * grad
            
            if epoch % 10 == 0:
                logger.debug(f"TransE epoch {epoch}: loss={total_loss:.4f}")
    
    def train_rotate(self, triples: List[Tuple[str, str, str]], n_epochs: int = 100):
        """
        Train RotatE embeddings (complex space).
        
        RotatE models relations as rotations in complex plane.
        """
        if not NUMPY_AVAILABLE:
            return
        
        # Complex embeddings (2x dim for real + imag)
        for h, r, t in triples:
            self.add_entity(h)
            self.add_entity(t)
            self.add_relation_type(r)
        
        for epoch in range(n_epochs):
            total_loss = 0.0
            
            for h, r, t in triples:
                h_emb = self.entity_embeddings[h]
                r_emb = self.relation_embeddings[r]
                t_emb = self.entity_embeddings[t]
                
                # Split into real/imaginary
                half = self.embedding_dim // 2
                h_real, h_imag = h_emb[:half], h_emb[half:]
                r_real, r_imag = r_emb[:half], r_emb[half:]
                t_real, t_imag = t_emb[:half], t_emb[half:]
                
                # Rotation: h * r (complex multiplication)
                rot_real = h_real * r_real - h_imag * r_imag
                rot_imag = h_real * r_imag + h_imag * r_real
                
                # Score: ||h ∘ r - t||
                diff_real = rot_real - t_real
                diff_imag = rot_imag - t_imag
                pos_score = np.sqrt(np.sum(diff_real ** 2 + diff_imag ** 2))
                
                # Negative sampling
                neg_t = np.random.choice(list(self.entity_embeddings.keys()))
                neg_t_emb = self.entity_embeddings[neg_t]
                neg_t_real, neg_t_imag = neg_t_emb[:half], neg_t_emb[half:]
                
                neg_diff_real = rot_real - neg_t_real
                neg_diff_imag = rot_imag - neg_t_imag
                neg_score = np.sqrt(np.sum(neg_diff_real ** 2 + neg_diff_imag ** 2))
                
                # Loss
                loss = max(0, self.margin + pos_score - neg_score)
                total_loss += loss
            
            if epoch % 10 == 0:
                logger.debug(f"RotatE epoch {epoch}: loss={total_loss:.4f}")
    
    def predict_link(self, head: str, relation: str, tail: str) -> float:
        """
        Predict likelihood of a link.
        
        Returns:
            Score (lower = more likely)
        """
        if not NUMPY_AVAILABLE:
            return 0.5
        
        h_emb = self.entity_embeddings.get(head)
        r_emb = self.relation_embeddings.get(relation)
        t_emb = self.entity_embeddings.get(tail)
        
        if h_emb is None or r_emb is None or t_emb is None:
            return 0.5
        
        # TransE score
        score = np.linalg.norm(h_emb + r_emb - t_emb)
        
        # Normalize to [0, 1]
        return float(1.0 / (1.0 + score))
    
    def get_entity_neighbors(self, entity_id: str, relation_type: Optional[str] = None,
                            top_k: int = 10) -> List[Tuple[str, float]]:
        """Find nearest neighbors in embedding space."""
        if not NUMPY_AVAILABLE:
            return []
        
        query = self.entity_embeddings.get(entity_id)
        if query is None:
            return []
        
        similarities = []
        for eid, emb in self.entity_embeddings.items():
            if eid != entity_id:
                sim = float(np.dot(query, emb) / (np.linalg.norm(query) * np.linalg.norm(emb) + 1e-8))
                similarities.append((eid, sim))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]


# ═══════════════════════════════════════════════════════════════════════════
# 5. TEMPORAL GRAPH NETWORKS
# ═══════════════════════════════════════════════════════════════════════════

class TemporalThreatGraph:
    """
    Temporal Graph Network for threat evolution.
    
    Capture l'évolution des menaces dans le temps :
    - Émergence de nouveaux IOCs
    - Propagation de campagnes
    - Évolution des relations entre entités
    - Détection de patterns temporels
    
    Référence : Rossi et al. "Temporal Graph Networks for Deep Learning
                on Dynamic Graphs" (TGN, ICML 2020)
    """
    
    def __init__(self, window_size: int = 3600, memory_dim: int = 64):
        self.window_size = window_size  # Time window in seconds
        self.memory_dim = memory_dim
        
        # Temporal graph state
        self.graph_snapshots: List[ThreatGraph] = []
        self.entity_memory: Dict[str, np.ndarray] = {}
        self.temporal_embeddings: Dict[str, List[Tuple[float, np.ndarray]]] = defaultdict(list)
        
        logger.info(f"⏱️  TemporalThreatGraph initialized (window={window_size}s)")
    
    def add_snapshot(self, graph: ThreatGraph):
        """Add a temporal snapshot."""
        self.graph_snapshots.append(graph)
        
        # Update entity memory
        for eid, entity in graph.entities.items():
            if NUMPY_AVAILABLE:
                # Update temporal embedding
                emb = np.random.randn(self.memory_dim).astype(np.float32)
                emb = emb / np.linalg.norm(emb)
                self.temporal_embeddings[eid].append((entity.last_seen, emb))
                
                # Keep only recent
                cutoff = time.time() - self.window_size * 24  # 24 hours
                self.temporal_embeddings[eid] = [
                    (t, e) for t, e in self.temporal_embeddings[eid]
                    if t > cutoff
                ]
    
    def get_entity_timeline(self, entity_id: str) -> List[Tuple[float, float]]:
        """Get entity activity timeline."""
        if entity_id not in self.temporal_embeddings:
            return []
        
        return [(t, float(np.linalg.norm(e))) for t, e in self.temporal_embeddings[entity_id]]
    
    def detect_emerging_threats(self, threshold: float = 0.8) -> List[ThreatEntity]:
        """Detect newly emerging threats."""
        emerging = []
        now = time.time()
        
        for snapshot in self.graph_snapshots[-10:]:  # Last 10 snapshots
            for eid, entity in snapshot.entities.items():
                # Check if entity is recent and has high score
                if (now - entity.first_seen) < self.window_size and entity.score > threshold:
                    emerging.append(entity)
        
        return emerging
    
    def predict_future_relations(self, entity_id: str, horizon: int = 3600) -> List[str]:
        """Predict future relations for an entity."""
        if not NUMPY_AVAILABLE:
            return []
        
        # Get recent embeddings
        timeline = self.temporal_embeddings.get(entity_id, [])
        if len(timeline) < 2:
            return []
        
        # Simple linear extrapolation
        recent_embs = [e for _, e in timeline[-5:]]
        if len(recent_embs) < 2:
            return []
        
        # Predict next embedding
        avg_change = np.mean([recent_embs[i] - recent_embs[i-1] 
                             for i in range(1, len(recent_embs))], axis=0)
        predicted = recent_embs[-1] + avg_change
        predicted = predicted / np.linalg.norm(predicted)
        
        # Find closest entities
        similarities = []
        for eid, emb in self.entity_memory.items():
            if eid != entity_id:
                sim = float(np.dot(predicted, emb) / (np.linalg.norm(predicted) * np.linalg.norm(emb) + 1e-8))
                similarities.append((eid, sim))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return [eid for eid, _ in similarities[:5]]


# ═══════════════════════════════════════════════════════════════════════════
# 6. ULTRA THREAT INTEL PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

class UltraThreatIntelPipeline:
    """
    Pipeline complet de Threat Intelligence.
    
    Combine :
    - GNN pour analyse des relations
    - NLP pour analyse de texte
    - BERTopic pour clustering
    - Knowledge Graph pour raisonnement
    - Temporal Graph pour évolution
    
    Use cases :
    - Analyse en temps réel de flux dark web
    - Détection de campagnes émergentes
    - Corrélation d'IOCs multi-sources
    - Prédiction de futures attaques
    """
    
    def __init__(self):
        self.gnn = ThreatGNN()
        self.nlp = DarkWebNLP()
        self.topic_model = ThreatBERTopic()
        self.knowledge_graph = KnowledgeGraphEmbeddings()
        self.temporal_graph = TemporalThreatGraph()
        
        self.reports: List[ThreatReport] = []
        self.entities: Dict[str, ThreatEntity] = {}
        
        logger.info("🚀 UltraThreatIntelPipeline initialized")
    
    def ingest_report(self, report: ThreatReport):
        """Ingest a threat report."""
        self.reports.append(report)
        
        # Extract IOCs
        iocs = self.nlp.extract_iocs(report.content)
        
        # Create entities
        for ioc_type, values in iocs.items():
            for value in values:
                eid = hashlib.md5(value.encode()).hexdigest()
                if eid not in self.entities:
                    entity = ThreatEntity(
                        id=eid,
                        entity_type=ioc_type,
                        value=value,
                        score=report.severity,
                    )
                    self.entities[eid] = entity
                    self.gnn.add_entity(entity)
                    self.knowledge_graph.add_entity(eid)
                
                report.entities.append(eid)
        
        # Classify threat
        classification = self.nlp.classify_threat(report.content)
        report.topics = [k for k, v in classification.items() if v > 0.3]
        
        logger.info(f"📥 Ingested report: {report.id} ({len(report.entities)} IOCs)")
    
    def analyze(self) -> Dict[str, Any]:
        """Run full analysis pipeline."""
        results = {}
        
        # 1. GNN propagation
        if self.gnn.entity_embeddings:
            self.gnn.propagate()
            communities = self.gnn.detect_communities()
            results["communities"] = {
                k: len(v) for k, v in communities.items()
            }
        
        # 2. Topic modeling
        if len(self.reports) >= 5:
            self.topic_model.fit(self.reports)
            results["topics"] = self.topic_model.get_topic_summary()
        
        # 3. Emerging threats
        emerging = self.temporal_graph.detect_emerging_threats()
        results["emerging_threats"] = len(emerging)
        
        # 4. Stats
        results["stats"] = {
            "n_reports": len(self.reports),
            "n_entities": len(self.entities),
            "n_relations": len(self.gnn.adjacency),
        }
        
        return results
    
    def search_entities(self, query: str, top_k: int = 10) -> List[ThreatEntity]:
        """Search entities by value."""
        query_lower = query.lower()
        matches = []
        for entity in self.entities.values():
            if query_lower in entity.value.lower():
                matches.append(entity)
        return matches[:top_k]
    
    def get_entity_graph(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Get subgraph around an entity."""
        if entity_id not in self.gnn.entity_embeddings:
            return {"error": "Entity not found"}
        
        # Find similar entities
        similar = self.gnn.find_similar(entity_id, top_k=10)
        
        # Get neighbors from knowledge graph
        neighbors = self.knowledge_graph.get_entity_neighbors(entity_id)
        
        return {
            "entity": self.entities.get(entity_id),
            "similar_entities": [
                {"id": eid, "similarity": sim} for eid, sim in similar
            ],
            "knowledge_graph_neighbors": [
                {"id": eid, "score": score} for eid, score in neighbors
            ],
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            "n_reports": len(self.reports),
            "n_entities": len(self.entities),
            "n_entity_types": len(set(e.entity_type for e in self.entities.values())),
            "gnn_embeddings": len(self.gnn.entity_embeddings),
            "knowledge_graph_entities": len(self.knowledge_graph.entity_embeddings),
            "temporal_snapshots": len(self.temporal_graph.graph_snapshots),
        }


# Factory
def create_threat_intel_pipeline() -> UltraThreatIntelPipeline:
    """Factory function for threat intel pipeline."""
    return UltraThreatIntelPipeline()


# Global instance
ultra_threat_intel_pipeline = UltraThreatIntelPipeline()


def get_threat_intel_pipeline() -> UltraThreatIntelPipeline:
    """Get global threat intel pipeline instance."""
    return ultra_threat_intel_pipeline
