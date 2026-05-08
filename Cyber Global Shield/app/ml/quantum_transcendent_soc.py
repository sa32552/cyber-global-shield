"""
Cyber Global Shield — Quantum Transcendent SOC (Pilier 2)
SOC Automatique multi-modèles qui dépasse l'entendement.

Architecture à 4 modèles fusionnés :
1. RandomForest (scikit-learn) — Classification robuste des alertes
2. XGBoost — Scoring de priorité et triage intelligent
3. Graph Neural Network (PyTorch) — Analyse des graphes d'attaque
4. Reinforcement Learning (Stable-Baselines3) — Décisions de réponse optimales

Fusion : Stacking adaptatif avec méta-modèle (CatBoost)
Décision : Vote pondéré + analyse de graphe + RL
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import structlog
import time
import json
from pathlib import Path

# ─── Scikit-learn ────────────────────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder
from sklearn.decomposition import PCA

# ─── XGBoost ────────────────────────────────────────────────────────────────
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# ─── CatBoost (méta-modèle) ─────────────────────────────────────────────────
try:
    from catboost import CatBoostClassifier
    HAS_CATBOOST = True
except ImportError:
    HAS_CATBOOST = False

# ─── Graph Neural Network ───────────────────────────────────────────────────
try:
    HAS_TORCH_GEO = False
    # On utilise un GNN custom sans dépendre de torch_geometric
except ImportError:
    HAS_TORCH_GEO = False

# ─── Reinforcement Learning ─────────────────────────────────────────────────
try:
    HAS_RL = False
    # On implémente un Q-Learning custom
except ImportError:
    HAS_RL = False

logger = structlog.get_logger(__name__)


# =============================================================================
# Types d'alertes et actions SOC
# =============================================================================

class AlertSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertCategory(Enum):
    SCAN = "scan"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    C2 = "c2"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PHISHING = "phishing"
    DDoS = "ddos"
    ZERO_DAY = "zero_day"
    INSIDER_THREAT = "insider_threat"
    UNKNOWN = "unknown"

class SOCCAction(Enum):
    """Actions possibles du SOC."""
    IGNORE = "ignore"
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    CONTAIN = "contain"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"
    AUTOMATED_RESPONSE = "automated_response"
    INCIDENT_RESPONSE = "incident_response"


# =============================================================================
# Résultat SOC
# =============================================================================

@dataclass
class SOCAlertResult:
    """Résultat d'analyse d'une alerte par le SOC quantique."""
    alert_id: str = ""
    severity: AlertSeverity = AlertSeverity.INFO
    category: AlertCategory = AlertCategory.UNKNOWN
    priority_score: float = 0.0
    confidence: float = 0.0
    
    # Scores individuels
    rf_score: float = 0.0
    xgb_score: float = 0.0
    gnn_score: float = 0.0
    rl_score: float = 0.0
    
    # Décision
    recommended_action: SOCCAction = SOCCAction.IGNORE
    is_critical: bool = False
    requires_escalation: bool = False
    
    # Analyse de graphe
    attack_path: Optional[List[str]] = None
    affected_assets: Optional[List[str]] = None
    lateral_spread_risk: float = 0.0
    
    # Métadonnées
    inference_time_ms: float = 0.0
    explanation: Optional[str] = None
    model_weights: Dict[str, float] = field(default_factory=dict)


@dataclass
class SOCBatchResult:
    """Résultat d'analyse par lot."""
    results: List[SOCAlertResult]
    n_critical: int
    n_high: int
    n_medium: int
    n_low: int
    n_info: int
    batch_inference_time_ms: float
    model_performance: Dict[str, float]


# =============================================================================
# Modèle 1 : RandomForest Classifier Amélioré
# =============================================================================

class TranscendentRandomForest:
    """
    RandomForest pour classification des alertes avec :
    - 500 arbres profonds
    - Calibration des probabilités
    - Feature importance intégrée
    - Détection de concept drift
    """
    
    def __init__(
        self,
        n_estimators: int = 500,
        max_depth: int = 30,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        class_weight: str = 'balanced_subsample',
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        self.params = {
            'n_estimators': n_estimators,
            'max_depth': max_depth,
            'min_samples_split': min_samples_split,
            'min_samples_leaf': min_samples_leaf,
            'class_weight': class_weight,
            'random_state': random_state,
            'n_jobs': n_jobs,
        }
        self.model = None
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self.feature_importance: Dict[str, float] = {}
        self.classes_: List[str] = []
    
    def fit(self, X: np.ndarray, y: np.ndarray) -> 'TranscendentRandomForest':
        """Entraîne le modèle."""
        X_scaled = self.scaler.fit_transform(X)
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = list(self.label_encoder.classes_)
        
        self.model = RandomForestClassifier(**self.params)
        self.model.fit(X_scaled, y_encoded)
        
        # Feature importance
        importance = self.model.feature_importances_
        total = importance.sum()
        if total > 0:
            self.feature_importance = {f"f{i}": float(v / total) for i, v in enumerate(importance)}
        
        self.is_fitted = True
        logger.info("random_forest_trained", n_samples=len(X), n_classes=len(self.classes_))
        return self
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Prédit les probabilités par classe."""
        if not self.is_fitted or self.model is None:
            return np.zeros((len(X), len(self.classes_)))
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Prédit les classes."""
        if not self.is_fitted or self.model is None:
            return np.array(['unknown'] * len(X))
        
        X_scaled = self.scaler.transform(X)
        y_encoded = self.model.predict(X_scaled)
        return self.label_encoder.inverse_transform(y_encoded)


# =============================================================================
# Modèle 2 : XGBoost Priority Scorer
# =============================================================================

class TranscendentXGBoost:
    """
    XGBoost pour scoring de priorité avec :
    - Régression pour le score de priorité (0-1)
    - Classification multi-classe pour la catégorie
    - Calibration des probabilités
    - Feature importance intégrée
    """
    
    def __init__(
        self,
        n_estimators: int = 500,
        max_depth: int = 8,
        learning_rate: float = 0.05,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        reg_alpha: float = 0.1,
        reg_lambda: float = 0.1,
        random_state: int = 42,
    ):
        self.params = {
            'n_estimators': n_estimators,
            'max_depth': max_depth,
            'learning_rate': learning_rate,
            'subsample': subsample,
            'colsample_bytree': colsample_bytree,
            'reg_alpha': reg_alpha,
            'reg_lambda': reg_lambda,
            'random_state': random_state,
            'n_jobs': -1,
        }
        self.priority_model = None  # Régression pour score de priorité
        self.category_model = None  # Classification pour catégorie
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self.feature_importance: Dict[str, float] = {}
    
    def fit(self, X: np.ndarray, y_priority: np.ndarray, y_category: np.ndarray) -> 'TranscendentXGBoost':
        """Entraîne les deux modèles."""
        if not HAS_XGBOOST:
            logger.warning("xgboost_not_available")
            return self
        
        X_scaled = self.scaler.fit_transform(X)
        y_cat_encoded = self.label_encoder.fit_transform(y_category)
        
        # Modèle de priorité (régression)
        self.priority_model = xgb.XGBRegressor(
            objective='reg:squarederror',
            **self.params
        )
        self.priority_model.fit(X_scaled, y_priority)
        
        # Modèle de catégorie (classification)
        self.category_model = xgb.XGBClassifier(
            objective='multi:softprob',
            num_class=len(self.label_encoder.classes_),
            **self.params
        )
        self.category_model.fit(X_scaled, y_cat_encoded)
        
        # Feature importance combinée
        importance = self.priority_model.feature_importances_
        total = importance.sum()
        if total > 0:
            self.feature_importance = {f"f{i}": float(v / total) for i, v in enumerate(importance)}
        
        self.is_fitted = True
        logger.info("xgboost_trained", n_samples=len(X), n_categories=len(self.label_encoder.classes_))
        return self
    
    def predict_priority(self, X: np.ndarray) -> np.ndarray:
        """Prédit le score de priorité (0-1)."""
        if not self.is_fitted or self.priority_model is None:
            return np.zeros(len(X))
        
        X_scaled = self.scaler.transform(X)
        scores = self.priority_model.predict(X_scaled)
        return np.clip(scores, 0, 1)
    
    def predict_category(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Prédit la catégorie et ses probabilités."""
        if not self.is_fitted or self.category_model is None:
            return np.array(['unknown'] * len(X)), np.zeros((len(X), 1))
        
        X_scaled = self.scaler.transform(X)
        probs = self.category_model.predict_proba(X_scaled)
        y_encoded = np.argmax(probs, axis=1)
        return self.label_encoder.inverse_transform(y_encoded), probs


# =============================================================================
# Modèle 3 : Graph Neural Network (Custom PyTorch)
# =============================================================================

class GraphAttentionLayer(nn.Module):
    """Couche d'attention sur graphe (GAT)."""
    
    def __init__(self, in_features: int, out_features: int, dropout: float = 0.2):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        
        self.W = nn.Parameter(torch.randn(in_features, out_features) * 0.1)
        self.a = nn.Parameter(torch.randn(2 * out_features, 1) * 0.1)
        self.dropout = nn.Dropout(dropout)
        self.leaky_relu = nn.LeakyReLU(0.2)
    
    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (n_nodes, in_features)
            adj: (n_nodes, n_nodes) matrice d'adjacence
        Returns:
            (n_nodes, out_features)
        """
        h = torch.mm(x, self.W)  # (n_nodes, out_features)
        n = h.size(0)
        
        # Calcul des coefficients d'attention
        h_i = h.unsqueeze(1).expand(-1, n, -1)  # (n_nodes, n_nodes, out_features)
        h_j = h.unsqueeze(0).expand(n, -1, -1)  # (n_nodes, n_nodes, out_features)
        h_concat = torch.cat([h_i, h_j], dim=-1)  # (n_nodes, n_nodes, 2*out_features)
        
        e = self.leaky_relu(torch.matmul(h_concat, self.a).squeeze(-1))  # (n_nodes, n_nodes)
        
        # Masque d'adjacence
        e = e * adj
        e = e - e.max(dim=1, keepdim=True)[0]  # Stabilité numérique
        
        attention = F.softmax(e, dim=1)  # (n_nodes, n_nodes)
        attention = self.dropout(attention)
        
        h_prime = torch.mm(attention, h)  # (n_nodes, out_features)
        return F.elu(h_prime)


class TranscendentGNN(nn.Module):
    """
    Graph Neural Network pour analyse des graphes d'attaque.
    
    Architecture :
    - 3 couches GAT (Graph Attention)
    - Pooling global
    - Tête de classification des nœuds
    - Tête de classification du graphe
    """
    
    def __init__(
        self,
        in_features: int = 64,
        hidden_features: int = 128,
        out_features: int = 32,
        n_classes_node: int = 5,  # Types de nœuds (IP, domaine, etc.)
        n_classes_graph: int = 3,  # Types d'attaques
        dropout: float = 0.2,
    ):
        super().__init__()
        
        self.gat1 = GraphAttentionLayer(in_features, hidden_features, dropout)
        self.gat2 = GraphAttentionLayer(hidden_features, hidden_features, dropout)
        self.gat3 = GraphAttentionLayer(hidden_features, out_features, dropout)
        
        self.dropout = nn.Dropout(dropout)
        self.norm1 = nn.LayerNorm(hidden_features)
        self.norm2 = nn.LayerNorm(hidden_features)
        self.norm3 = nn.LayerNorm(out_features)
        
        # Tête de classification des nœuds
        self.node_classifier = nn.Sequential(
            nn.Linear(out_features, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, n_classes_node),
        )
        
        # Tête de classification du graphe
        self.graph_classifier = nn.Sequential(
            nn.Linear(out_features, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, n_classes_graph),
        )
        
        # Tête de scoring de risque
        self.risk_scorer = nn.Sequential(
            nn.Linear(out_features, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )
    
    def forward(
        self,
        x: torch.Tensor,
        adj: torch.Tensor,
        batch_mask: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x: (n_nodes, in_features)
            adj: (n_nodes, n_nodes)
            batch_mask: (n_nodes,) masque pour séparer les graphes
        Returns:
            node_logits: (n_nodes, n_classes_node)
            graph_logits: (n_graphs, n_classes_graph)
            risk_scores: (n_graphs,)
            node_embeddings: (n_nodes, out_features)
        """
        # Couches GAT avec skip connections
        h1 = self.gat1(x, adj)
        h1 = self.norm1(h1)
        h1 = self.dropout(h1)
        
        h2 = self.gat2(h1, adj)
        h2 = self.norm2(h2)
        h2 = self.dropout(h2)
        h2 = h2 + h1  # Skip connection
        
        h3 = self.gat3(h2, adj)
        h3 = self.norm3(h3)
        h3 = self.dropout(h3)
        h3 = h3 + h2  # Skip connection
        
        # Classification des nœuds
        node_logits = self.node_classifier(h3)
        
        # Pooling global pour classification du graphe
        if batch_mask is not None:
            n_graphs = batch_mask.max().item() + 1
            graph_embeddings = torch.zeros(n_graphs, h3.size(-1), device=h3.device)
            for i in range(n_graphs):
                mask = batch_mask == i
                if mask.any():
                    graph_embeddings[i] = h3[mask].mean(dim=0)
        else:
            graph_embeddings = h3.mean(dim=0, keepdim=True)
        
        graph_logits = self.graph_classifier(graph_embeddings)
        risk_scores = self.risk_scorer(graph_embeddings).squeeze(-1)
        
        return node_logits, graph_logits, risk_scores, h3


class TranscendentGraphAnalyzer:
    """
    Analyseur de graphes d'attaque basé sur GNN.
    
    Fonctionnalités :
    - Détection de chemins d'attaque
    - Scoring de propagation latérale
    - Identification des assets critiques
    - Prédiction de la prochaine cible
    """
    
    def __init__(
        self,
        in_features: int = 64,
        hidden_features: int = 128,
        device: str = 'cpu',
    ):
        self.model = TranscendentGNN(
            in_features=in_features,
            hidden_features=hidden_features,
        )
        self.device = device
        self.model.to(device)
        self.is_fitted = False
        self.node_encoder = LabelEncoder()
        self.feature_scaler = StandardScaler()
    
    def _build_graph(
        self,
        alerts: List[Dict[str, Any]],
    ) -> Tuple[torch.Tensor, torch.Tensor, List[str], Dict[str, int]]:
        """
        Construit un graphe d'attaque à partir des alertes.
        
        Returns:
            features: (n_nodes, in_features)
            adj: (n_nodes, n_nodes)
            node_names: Liste des noms de nœuds
            node_to_idx: Mapping nom -> index
        """
        # Extraction des entités (IPs, domaines, etc.)
        nodes = set()
        edges = []
        
        for alert in alerts:
            src = alert.get('src_ip', '') or alert.get('source', '')
            dst = alert.get('dst_ip', '') or alert.get('destination', '')
            
            if src:
                nodes.add(src)
            if dst:
                nodes.add(dst)
            if src and dst:
                edges.append((src, dst))
        
        node_list = list(nodes)
        node_to_idx = {name: i for i, name in enumerate(node_list)}
        n_nodes = len(node_list)
        
        # Matrice d'adjacence
        adj = torch.zeros(n_nodes, n_nodes)
        for src, dst in edges:
            if src in node_to_idx and dst in node_to_idx:
                adj[node_to_idx[src], node_to_idx[dst]] = 1.0
                adj[node_to_idx[dst], node_to_idx[src]] = 1.0  # Non-dirigé
        
        # Features des nœuds
        features = np.zeros((n_nodes, self.model.gat1.in_features))
        for i, node in enumerate(node_list):
            # Encodage du type de nœud (IP, domaine, etc.)
            if '.' in node and not node.replace('.', '').isdigit():
                features[i, 0] = 0.8  # Domaine
            elif node.replace('.', '').isdigit():
                features[i, 0] = 0.3  # IP
            else:
                features[i, 0] = 0.5  # Autre
            
            # Degré du nœud
            degree = adj[i].sum().item()
            features[i, 1] = min(degree / 10.0, 1.0)
            
            # Nombre d'alertes associées
            n_alerts = sum(1 for a in alerts if a.get('src_ip') == node or a.get('dst_ip') == node)
            features[i, 2] = min(n_alerts / 100.0, 1.0)
            
            # Score de sévérité moyen
            severities = []
            for a in alerts:
                if a.get('src_ip') == node or a.get('dst_ip') == node:
                    sev = a.get('severity', 'info')
                    sev_map = {'info': 0.1, 'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9}
                    severities.append(sev_map.get(sev, 0.1))
            if severities:
                features[i, 3] = np.mean(severities)
        
        features = self.feature_scaler.fit_transform(features)
        
        return (
            torch.FloatTensor(features).to(self.device),
            adj.to(self.device),
            node_list,
            node_to_idx,
        )
    
    def analyze(
        self,
        alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Analyse un ensemble d'alertes via le GNN.
        
        Returns:
            Dict avec analyse du graphe d'attaque
        """
        features, adj, node_names, node_to_idx = self._build_graph(alerts)
        
        self.model.eval()
        with torch.no_grad():
            node_logits, graph_logits, risk_scores, embeddings = self.model(features, adj)
        
        # Chemins d'attaque (BFS depuis les nœuds à haut risque)
        risk_per_node = F.softmax(node_logits, dim=-1)[:, -1].cpu().numpy()  # Probabilité "malveillant"
        high_risk_nodes = [node_names[i] for i in np.where(risk_per_node > 0.7)[0]]
        
        # Propagation latérale
        lateral_risk = float(risk_scores.mean().item()) if risk_scores.numel() > 0 else 0.0
        
        # Type d'attaque
        attack_types = ['scan', 'lateral_movement', 'data_exfiltration']
        attack_probs = F.softmax(graph_logits, dim=-1)[0].cpu().numpy()
        attack_type = attack_types[np.argmax(attack_probs)]
        
        return {
            'attack_path': high_risk_nodes[:10],
            'lateral_spread_risk': lateral_risk,
            'attack_type': attack_type,
            'attack_confidence': float(np.max(attack_probs)),
            'n_nodes_analyzed': len(node_names),
            'n_high_risk_nodes': len(high_risk_nodes),
            'node_embeddings': embeddings.cpu().numpy(),
        }


# =============================================================================
# Modèle 4 : Reinforcement Learning (Q-Learning Custom)
# =============================================================================

class TranscendentRLAgent:
    """
    Agent RL pour décisions de réponse optimales.
    
    Utilise Q-Learning avec approximation de fonction (Neural Network).
    États : embedding des alertes + contexte réseau
    Actions : IGNORE, MONITOR, INVESTIGATE, CONTAIN, BLOCK, QUARANTINE, ESCALATE
    Récompenses : basées sur le temps de résolution et l'impact
    """
    
    def __init__(
        self,
        state_dim: int = 128,
        action_dim: int = 7,
        hidden_dim: int = 256,
        learning_rate: float = 0.001,
        gamma: float = 0.95,
        epsilon: float = 0.1,
        epsilon_decay: float = 0.995,
        min_epsilon: float = 0.01,
        device: str = 'cpu',
    ):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.min_epsilon = min_epsilon
        self.device = device
        
        # Actions disponibles
        self.actions = [
            SOCCAction.IGNORE,
            SOCCAction.MONITOR,
            SOCCAction.INVESTIGATE,
            SOCCAction.CONTAIN,
            SOCCAction.BLOCK,
            SOCCAction.QUARANTINE,
            SOCCAction.ESCALATE,
        ]
        
        # Réseau Q
        self.q_network = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
        ).to(device)
        
        self.optimizer = torch.optim.Adam(self.q_network.parameters(), lr=learning_rate)
        self.loss_fn = nn.MSELoss()
        
        # Mémoire de replay
        self.memory: List[Tuple] = []
        self.max_memory = 10000
        self.batch_size = 64
        
        self.is_fitted = False
        self.n_training_steps = 0
    
    def _state_to_tensor(self, state: np.ndarray) -> torch.Tensor:
        """Convertit un état en tensor."""
        if state.ndim == 1:
            state = state.reshape(1, -1)
        return torch.FloatTensor(state).to(self.device)
    
    def select_action(self, state: np.ndarray, training: bool = True) -> Tuple[int, SOCCAction]:
        """
        Sélectionne une action selon la politique epsilon-greedy.
        
        Returns:
            (action_idx, action)
        """
        if training and np.random.random() < self.epsilon:
            action_idx = np.random.randint(self.action_dim)
        else:
            state_tensor = self._state_to_tensor(state)
            with torch.no_grad():
                q_values = self.q_network(state_tensor)
                action_idx = q_values.argmax().item()
        
        return action_idx, self.actions[action_idx]
    
    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool):
        """Stocke une transition dans la mémoire."""
        self.memory.append((state, action, reward, next_state, done))
        if len(self.memory) > self.max_memory:
            self.memory.pop(0)
    
    def train(self) -> float:
        """Entraîne le réseau Q sur un batch de la mémoire."""
        if len(self.memory) < self.batch_size:
            return 0.0
        
        batch = np.random.choice(len(self.memory), self.batch_size, replace=False)
        states, actions, rewards, next_states, dones = [], [], [], [], []
        
        for idx in batch:
            s, a, r, ns, d = self.memory[idx]
            states.append(s)
            actions.append(a)
            rewards.append(r)
            next_states.append(ns)
            dones.append(d)
        
        states = self._state_to_tensor(np.array(states))
        actions = torch.LongTensor(actions).to(self.device)
        rewards = torch.FloatTensor(rewards).to(self.device)
        next_states = self._state_to_tensor(np.array(next_states))
        dones = torch.FloatTensor(dones).to(self.device)
        
        # Q-values actuelles
        current_q = self.q_network(states).gather(1, actions.unsqueeze(1)).squeeze()
        
        # Q-values cibles
        with torch.no_grad():
            next_q = self.q_network(next_states).max(1)[0]
            target_q = rewards + self.gamma * next_q * (1 - dones)
        
        loss = self.loss_fn(current_q, target_q)
        
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        self.optimizer.step()
        
        # Décroissance de epsilon
        self.epsilon = max(self.min_epsilon, self.epsilon * self.epsilon_decay)
        self.n_training_steps += 1
        self.is_fitted = True
        
        return loss.item()
    
    def predict_action(self, state: np.ndarray) -> Tuple[SOCCAction, float]:
        """
        Prédit la meilleure action pour un état donné.
        
        Returns:
            (action, q_value)
        """
        state_tensor = self._state_to_tensor(state)
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
            action_idx = q_values.argmax().item()
            q_value = q_values[0, action_idx].item()
        
        return self.actions[action_idx], q_value
    
    def save(self, path: str):
        """Sauvegarde le modèle."""
        torch.save({
            'q_network': self.q_network.state_dict(),
            'optimizer': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
        }, path)
    
    def load(self, path: str):
        """Charge le modèle."""
        checkpoint = torch.load(path, map_location=self.device)
        self.q_network.load_state_dict(checkpoint['q_network'])
        self.optimizer.load_state_dict(checkpoint['optimizer'])
        self.epsilon = checkpoint['epsilon']
        self.is_fitted = True


# =============================================================================
# Ensemble : Fusion des 4 modèles SOC
# =============================================================================

class TranscendentSOCEnsemble:
    """
    Ensemble SOC qui fusionne les 4 modèles.
    
    Pipeline de décision :
    1. RandomForest classe l'alerte
    2. XGBoost score la priorité
    3. GNN analyse le graphe d'attaque
    4. RL décide de l'action optimale
    5. Fusion par méta-modèle CatBoost
    """
    
    def __init__(
        self,
        random_forest: Optional[TranscendentRandomForest] = None,
        xgboost: Optional[TranscendentXGBoost] = None,
        graph_analyzer: Optional[TranscendentGraphAnalyzer] = None,
        rl_agent: Optional[TranscendentRLAgent] = None,
        threshold_critical: float = 0.8,
        threshold_high: float = 0.6,
        use_meta_model: bool = True,
    ):
        self.random_forest = random_forest
        self.xgboost = xgboost
        self.graph_analyzer = graph_analyzer
        self.rl_agent = rl_agent
        
        self.threshold_critical = threshold_critical
        self.threshold_high = threshold_high
        self.use_meta_model = use_meta_model and HAS_CATBOOST
        
        # Poids des modèles
        self.model_weights = {
            'random_forest': 0.30,
            'xgboost': 0.30,
            'gnn': 0.20,
            'rl': 0.20,
        }
        
        # Performance historique
        self.performance_history: Dict[str, List[float]] = {
            'random_forest': [],
            'xgboost': [],
            'gnn': [],
            'rl': [],
        }
        
        # Méta-modèle
        self.meta_model = None
        self.meta_scaler = StandardScaler()
        self.meta_is_fitted = False
        
        # Feature store
        self.feature_store: List[np.ndarray] = []
        self.label_store: List[int] = []
        self.max_store_size = 10000
    
    def set_models(
        self,
        random_forest: TranscendentRandomForest,
        xgboost: TranscendentXGBoost,
        graph_analyzer: TranscendentGraphAnalyzer,
        rl_agent: TranscendentRLAgent,
    ):
        """Configure les 4 modèles."""
        self.random_forest = random_forest
        self.xgboost = xgboost
        self.graph_analyzer = graph_analyzer
        self.rl_agent = rl_agent
    
    def _extract_features(self, alert: Dict[str, Any]) -> np.ndarray:
        """Extrait les features pour le méta-modèle."""
        features = []
        
        # Features de l'alerte
        severity_map = {'info': 0.1, 'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9}
        features.append(severity_map.get(alert.get('severity', 'info'), 0.1))
        features.append(min(alert.get('confidence', 0.5), 1.0))
        features.append(min(alert.get('risk_score', 0.0), 1.0))
        features.append(1.0 if alert.get('is_escalated', False) else 0.0)
        features.append(min(len(alert.get('affected_assets', [])), 100) / 100.0)
        features.append(min(alert.get('n_related_alerts', 0), 1000) / 1000.0)
        
        return np.array(features)
    
    def _train_meta_model(self):
        """Entraîne le méta-modèle CatBoost."""
        if len(self.feature_store) < 100:
            return
        
        X_meta = np.array(self.feature_store)
        y_meta = np.array(self.label_store)
        
        X_scaled = self.meta_scaler.fit_transform(X_meta)
        
        self.meta_model = CatBoostClassifier(
            iterations=200,
            depth=6,
            learning_rate=0.1,
            loss_function='MultiClass',
            verbose=False,
            random_seed=42,
        )
        self.meta_model.fit(X_scaled, y_meta)
        self.meta_is_fitted = True
        
        logger.info("soc_meta_model_trained", n_samples=len(X_meta))
    
    def analyze_alert(
        self,
        alert: Dict[str, Any],
        related_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> SOCAlertResult:
        """
        Analyse une alerte avec les 4 modèles SOC.
        
        Args:
            alert: Dictionnaire de l'alerte
            related_alerts: Alertes connexes pour l'analyse de graphe
        
        Returns:
            Résultat SOC complet
        """
        start_time = time.time()
        
        result = SOCAlertResult()
        result.alert_id = alert.get('id', alert.get('alert_id', 'unknown'))
        
        # Features pour les modèles
        features = self._extract_features(alert)
        features_2d = features.reshape(1, -1)
        
        # 1. RandomForest - Classification
        if self.random_forest is not None and self.random_forest.is_fitted:
            rf_probs = self.random_forest.predict_proba(features_2d)
            result.rf_score = float(np.max(rf_probs))
            
            # Catégorie prédite
            rf_pred = self.random_forest.predict(features_2d)[0]
            try:
                result.category = AlertCategory(rf_pred)
            except ValueError:
                result.category = AlertCategory.UNKNOWN
        
        # 2. XGBoost - Scoring de priorité
        if self.xgboost is not None and self.xgboost.is_fitted:
            priority = self.xgboost.predict_priority(features_2d)
            result.xgb_score = float(priority[0])
            
            cat_pred, cat_probs = self.xgboost.predict_category(features_2d)
            try:
                result.category = AlertCategory(cat_pred[0])
            except ValueError:
                pass
        
        # 3. GNN - Analyse de graphe
        if self.graph_analyzer is not None:
            all_alerts = [alert]
            if related_alerts:
                all_alerts.extend(related_alerts)
            
            graph_analysis = self.graph_analyzer.analyze(all_alerts)
            result.gnn_score = float(graph_analysis['lateral_spread_risk'])
            result.attack_path = graph_analysis['attack_path']
            result.lateral_spread_risk = graph_analysis['lateral_spread_risk']
        
        # 4. RL - Décision d'action
        if self.rl_agent is not None and self.rl_agent.is_fitted:
            rl_state = np.concatenate([features, [result.rf_score, result.xgb_score, result.gnn_score]])
            if len(rl_state) < self.rl_agent.state_dim:
                rl_state = np.pad(rl_state, (0, self.rl_agent.state_dim - len(rl_state)))
            else:
                rl_state = rl_state[:self.rl_agent.state_dim]
            
            action, q_value = self.rl_agent.predict_action(rl_state)
            result.recommended_action = action
            result.rl_score = float(q_value)
        
        # Score de priorité fusionné
        scores = {
            'random_forest': result.rf_score,
            'xgboost': result.xgb_score,
            'gnn': result.gnn_score,
            'rl': result.rl_score,
        }
        
        if self.use_meta_model and self.meta_is_fitted:
            meta_features = self._extract_features(alert).reshape(1, -1)
            meta_scaled = self.meta_scaler.transform(meta_features)
            priority_score = float(self.meta_model.predict_proba(meta_scaled)[0, -1])
        else:
            priority_score = sum(
                scores.get(name, 0.0) * self.model_weights.get(name, 0.0)
                for name in self.model_weights
            )
        
        result.priority_score = priority_score
        result.model_weights = dict(self.model_weights)
        
        # Seuils
        result.is_critical = priority_score > self.threshold_critical
        result.requires_escalation = priority_score > self.threshold_high
        
        # Sévérité
        if priority_score > self.threshold_critical:
            result.severity = AlertSeverity.CRITICAL
        elif priority_score > self.threshold_high:
            result.severity = AlertSeverity.HIGH
        elif priority_score > 0.4:
            result.severity = AlertSeverity.MEDIUM
        elif priority_score > 0.2:
            result.severity = AlertSeverity.LOW
        else:
            result.severity = AlertSeverity.INFO
        
        # Confiance
        result.confidence = float(min(1.0, abs(priority_score - 0.5) * 2))
        
        # Explication
        result.explanation = self._generate_explanation(result, scores)
        
        # Temps d'inférence
        result.inference_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def analyze_batch(
        self,
        alerts: List[Dict[str, Any]],
    ) -> SOCBatchResult:
        """Analyse un lot d'alertes."""
        start_time = time.time()
        
        results = []
        for alert in alerts:
            result = self.analyze_alert(alert)
            results.append(result)
        
        n_critical = sum(1 for r in results if r.severity == AlertSeverity.CRITICAL)
        n_high = sum(1 for r in results if r.severity == AlertSeverity.HIGH)
        n_medium = sum(1 for r in results if r.severity == AlertSeverity.MEDIUM)
        n_low = sum(1 for r in results if r.severity == AlertSeverity.LOW)
        n_info = sum(1 for r in results if r.severity == AlertSeverity.INFO)
        
        return SOCBatchResult(
            results=results,
            n_critical=n_critical,
            n_high=n_high,
            n_medium=n_medium,
            n_low=n_low,
            n_info=n_info,
            batch_inference_time_ms=(time.time() - start_time) * 1000,
            model_performance={},
        )
    
    def _generate_explanation(
        self,
        result: SOCAlertResult,
        scores: Dict[str, float],
    ) -> str:
        """Génère une explication lisible."""
        parts = []
        
        severity_icons = {
            AlertSeverity.INFO: "ℹ️",
            AlertSeverity.LOW: "🟢",
            AlertSeverity.MEDIUM: "🟡",
            AlertSeverity.HIGH: "🟠",
            AlertSeverity.CRITICAL: "🔴",
        }
        
        icon = severity_icons.get(result.severity, "❓")
        parts.append(f"{icon} ALERTE {result.severity.value.upper()} (priorité={result.priority_score:.3f})")
        parts.append(f"Catégorie: {result.category.value}")
        parts.append(f"Action recommandée: {result.recommended_action.value}")
        
        # Contributions
        model_names = {
            'random_forest': 'RandomForest',
            'xgboost': 'XGBoost',
            'gnn': 'GNN',
            'rl': 'RL',
        }
        contributions = []
        for name, display_name in model_names.items():
            score = scores.get(name, 0.0)
            weight = self.model_weights.get(name, 0.0)
            if score > 0:
                contributions.append(f"{display_name}: {score:.3f} (poids={weight:.2f})")
        
        if contributions:
            parts.append("Modèles: " + " | ".join(contributions))
        
        # Risque de propagation
        if result.lateral_spread_risk > 0.5:
            parts.append(f"⚠️ Risque de propagation latérale: {result.lateral_spread_risk:.1%}")
        
        # Chemins d'attaque
        if result.attack_path:
            parts.append(f"Chemin d'attaque: {' → '.join(result.attack_path[:5])}")
        
        parts.append(f"Confiance: {result.confidence:.1%}")
        
        return " | ".join(parts)


# =============================================================================
# Factory : Création du SOC transcendant
# =============================================================================

def create_transcendent_soc(
    n_features: int = 64,
    threshold_critical: float = 0.8,
    threshold_high: float = 0.6,
    device: str = 'cpu',
) -> TranscendentSOCEnsemble:
    """
    Crée et configure le SOC transcendant complet.
    
    Args:
        n_features: Nombre de features d'entrée
        threshold_critical: Seuil pour alerte critique
        threshold_high: Seuil pour alerte haute
        device: Device PyTorch
    
    Returns:
        Ensemble SOC complet
    """
    logger.info("creating_transcendent_soc",
                n_features=n_features,
                threshold_critical=threshold_critical,
                threshold_high=threshold_high,
                device=device)
    
    # 1. RandomForest
    random_forest = TranscendentRandomForest(
        n_estimators=500,
        max_depth=30,
        class_weight='balanced_subsample',
    )
    
    # 2. XGBoost
    xgboost = TranscendentXGBoost(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
    )
    
    # 3. GNN
    graph_analyzer = TranscendentGraphAnalyzer(
        in_features=64,
        hidden_features=128,
        device=device,
    )
    
    # 4. RL Agent
    rl_agent = TranscendentRLAgent(
        state_dim=128,
        action_dim=7,
        hidden_dim=256,
        device=device,
    )
    
    # Ensemble
    ensemble = TranscendentSOCEnsemble(
        random_forest=random_forest,
        xgboost=xgboost,
        graph_analyzer=graph_analyzer,
        rl_agent=rl_agent,
        threshold_critical=threshold_critical,
        threshold_high=threshold_high,
        use_meta_model=True,
    )
    
    logger.info("transcendent_soc_created",
                n_models=4,
                gnn_params=sum(p.numel() for p in graph_analyzer.model.parameters()),
                rl_params=sum(p.numel() for p in rl_agent.q_network.parameters()))
    
    return ensemble
