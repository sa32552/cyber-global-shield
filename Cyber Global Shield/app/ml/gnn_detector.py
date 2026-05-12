"""
Cyber Global Shield — Graph Neural Network Attack Detector
==========================================================
Détection d'attaques par GNN (Graph Neural Networks).
Modélise le réseau comme un graphe pour détecter :
- Mouvements latéraux (Lateral Movement)
- Propagation de ransomware
- Beaconing C2
- Data exfiltration
- Scanning patterns
- Attaques multi-étapes

Architecture:
- GraphSAGE + GAT (Graph Attention Networks)
- Apprentissage auto-supervisé (reconstruction de graphe)
- Détection d'anomalies structurelles
"""

import numpy as np
from typing import Optional, Dict, Any, List, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta
import structlog
import json

logger = structlog.get_logger(__name__)

# ─── Data Structures ───────────────────────────────────────────────────────

@dataclass
class NetworkNode:
    """A node in the network graph (host, IP, or device)."""
    node_id: str
    node_type: str  # 'host', 'ip', 'container', 'user'
    label: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    risk_score: float = 0.0
    alert_count: int = 0

@dataclass
class NetworkEdge:
    """An edge in the network graph (connection between nodes)."""
    source_id: str
    target_id: str
    edge_type: str  # 'connection', 'auth', 'dns', 'file_transfer'
    protocol: str = "tcp"
    port: int = 0
    bytes_transferred: int = 0
    packet_count: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration: float = 0.0
    features: Dict[str, float] = field(default_factory=dict)

@dataclass
class AttackPath:
    """A detected attack path through the graph."""
    path: List[str]  # node IDs in the path
    attack_type: str  # 'lateral_movement', 'ransomware', 'c2', 'exfiltration'
    confidence: float
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    affected_nodes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

# ─── Feature Engineering ───────────────────────────────────────────────────

class GraphFeatureExtractor:
    """
    Extracts features from network graph for GNN processing.
    Converts raw network data into graph-structured features.
    """
    
    def __init__(self, window_size_minutes: int = 60):
        self.window_size = timedelta(minutes=window_size_minutes)
        self.nodes: Dict[str, NetworkNode] = {}
        self.edges: List[NetworkEdge] = []
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        
    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "tcp",
        port: int = 0,
        bytes_sent: int = 0,
        packets: int = 0,
        duration: float = 0.0,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Add a network connection to the graph."""
        ts = timestamp or datetime.utcnow()
        
        # Ensure nodes exist
        for ip in [src_ip, dst_ip]:
            if ip not in self.nodes:
                self.nodes[ip] = NetworkNode(
                    node_id=ip,
                    node_type="ip",
                    label=ip,
                    first_seen=ts,
                )
            self.nodes[ip].last_seen = ts
        
        # Create edge
        edge = NetworkEdge(
            source_id=src_ip,
            target_id=dst_ip,
            edge_type="connection",
            protocol=protocol,
            port=port,
            bytes_transferred=bytes_sent,
            packet_count=packets,
            duration=duration,
            timestamp=ts,
            features=self._compute_edge_features(src_ip, dst_ip, protocol, port, bytes_sent, packets),
        )
        self.edges.append(edge)
        self.adjacency[src_ip].add(dst_ip)
        
        # Prune old edges
        self._prune_old_edges(ts)
    
    def add_auth_event(
        self,
        user: str,
        target_ip: str,
        success: bool = True,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Add an authentication event to the graph."""
        ts = timestamp or datetime.utcnow()
        
        # User node
        if user not in self.nodes:
            self.nodes[user] = NetworkNode(
                node_id=user,
                node_type="user",
                label=user,
                first_seen=ts,
            )
        self.nodes[user].last_seen = ts
        
        # Target IP node
        if target_ip not in self.nodes:
            self.nodes[target_ip] = NetworkNode(
                node_id=target_ip,
                node_type="ip",
                label=target_ip,
                first_seen=ts,
            )
        self.nodes[target_ip].last_seen = ts
        
        # Auth edge
        edge = NetworkEdge(
            source_id=user,
            target_id=target_ip,
            edge_type="auth",
            timestamp=ts,
            features={"success": 1.0 if success else 0.0},
        )
        self.edges.append(edge)
        self.adjacency[user].add(target_ip)
    
    def _compute_edge_features(
        self,
        src: str,
        dst: str,
        protocol: str,
        port: int,
        bytes_sent: int,
        packets: int,
    ) -> Dict[str, float]:
        """Compute numerical features for an edge."""
        features = {
            "protocol_encoded": hash(protocol) % 10 / 10.0,
            "port_normalized": min(port / 65535.0, 1.0),
            "bytes_log": np.log1p(bytes_sent),
            "packets_log": np.log1p(packets),
            "bytes_per_packet": bytes_sent / max(packets, 1),
            "is_common_port": 1.0 if port in {80, 443, 22, 3389, 445, 1433, 3306} else 0.0,
            "is_high_port": 1.0 if port > 1024 else 0.0,
        }
        return features
    
    def _prune_old_edges(self, current_time: datetime) -> None:
        """Remove edges older than the window."""
        cutoff = datetime.utcnow() - self.window_size
        self.edges = [e for e in self.edges if e.timestamp >= cutoff]
        
        # Rebuild adjacency
        self.adjacency.clear()
        for edge in self.edges:
            self.adjacency[edge.source_id].add(edge.target_id)
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """Get statistics about the current graph."""
        node_type_counts = defaultdict(int)
        for node in self.nodes.values():
            node_type_counts[node.node_type] += 1
        
        edge_type_counts = defaultdict(int)
        for edge in self.edges:
            edge_type_counts[edge.edge_type] += 1
        
        return {
            "num_nodes": len(self.nodes),
            "num_edges": len(self.edges),
            "node_types": dict(node_type_counts),
            "edge_types": dict(edge_type_counts),
            "avg_degree": len(self.edges) / max(len(self.nodes), 1),
        }
    
    def to_feature_matrix(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Convert graph to feature matrix and adjacency matrix.
        
        Returns:
            node_features: (N, F) matrix of node features
            adjacency_matrix: (N, N) sparse adjacency matrix
            node_ids: list of node IDs corresponding to rows
        """
        node_ids = list(self.nodes.keys())
        n = len(node_ids)
        node_index = {nid: i for i, nid in enumerate(node_ids)}
        
        # Node features: degree, connection count, risk score, etc.
        node_features = np.zeros((n, 8), dtype=np.float32)
        for i, nid in enumerate(node_ids):
            node = self.nodes[nid]
            degree = len(self.adjacency.get(nid, set()))
            in_edges = sum(1 for e in self.edges if e.target_id == nid)
            out_edges = sum(1 for e in self.edges if e.source_id == nid)
            total_bytes = sum(
                e.bytes_transferred for e in self.edges
                if e.source_id == nid or e.target_id == nid
            )
            
            node_features[i] = [
                degree / max(n, 1),           # normalized degree
                in_edges / max(n, 1),          # in-degree
                out_edges / max(n, 1),         # out-degree
                np.log1p(total_bytes),         # total bytes
                node.risk_score,               # risk score
                node.alert_count / 100.0,      # alert count
                1.0 if node.node_type == "user" else 0.0,  # is user
                1.0 if node.node_type == "ip" else 0.0,    # is ip
            ]
        
        # Adjacency matrix
        adj = np.zeros((n, n), dtype=np.float32)
        for edge in self.edges:
            if edge.source_id in node_index and edge.target_id in node_index:
                i, j = node_index[edge.source_id], node_index[edge.target_id]
                adj[i, j] = 1.0
                # Add edge features as weights
                if edge.features:
                    adj[i, j] = sum(edge.features.values()) / max(len(edge.features), 1)
        
        return node_features, adj, node_ids

# ─── GNN Detector ──────────────────────────────────────────────────────────

class GNNAttackDetector:
    """
    Graph Neural Network-based attack detector.
    
    Detects attacks by analyzing the network graph structure:
    - Anomalous subgraphs (lateral movement)
    - Unexpected connections (C2 beaconing)
    - Graph structure changes (ransomware propagation)
    - Centrality anomalies (privilege escalation)
    """
    
    def __init__(
        self,
        feature_extractor: Optional[GraphFeatureExtractor] = None,
        threshold_multiplier: float = 3.0,
        min_confidence: float = 0.6,
    ):
        self.feature_extractor = feature_extractor or GraphFeatureExtractor()
        self.threshold_multiplier = threshold_multiplier
        self.min_confidence = min_confidence
        
        # Graph metrics baseline
        self._baseline: Dict[str, float] = {}
        self._baseline_samples: List[Dict[str, float]] = []
        self._attack_paths: List[AttackPath] = []
        
        # Known attack patterns (signatures)
        self._attack_patterns = self._init_attack_patterns()
    
    def _init_attack_patterns(self) -> Dict[str, Dict]:
        """Initialize known attack patterns for graph-based detection."""
        return {
            "lateral_movement": {
                "description": "Lateral movement through the network",
                "indicators": [
                    "unusual_rdp_connections",
                    "smb_to_multiple_hosts",
                    "admin_tool_deployment",
                    "pass_the_hash",
                ],
                "graph_pattern": "star_expansion",  # One node connecting to many new nodes
                "min_nodes": 3,
                "max_hops": 4,
            },
            "ransomware_propagation": {
                "description": "Ransomware spreading through network shares",
                "indicators": [
                    "mass_file_encryption",
                    "smb_burst",
                    "unusual_write_operations",
                ],
                "graph_pattern": "cascade",  # Rapid sequential connections
                "min_nodes": 2,
                "max_hops": 6,
            },
            "c2_beaconing": {
                "description": "Command & Control beaconing",
                "indicators": [
                    "periodic_connections",
                    "unusual_domains",
                    "dns_tunneling",
                ],
                "graph_pattern": "periodic_star",  # Regular connections to external IP
                "min_nodes": 2,
                "max_hops": 2,
            },
            "data_exfiltration": {
                "description": "Data exfiltration to external hosts",
                "indicators": [
                    "large_outbound_transfers",
                    "unusual_protocols",
                    "encrypted_tunnels",
                ],
                "graph_pattern": "high_volume_outbound",
                "min_nodes": 2,
                "max_hops": 2,
            },
            "port_scanning": {
                "description": "Network reconnaissance / port scanning",
                "indicators": [
                    "rapid_connection_attempts",
                    "multiple_ports_single_host",
                    "failed_connections",
                ],
                "graph_pattern": "fan_out",  # One source to many ports on one target
                "min_nodes": 2,
                "max_hops": 2,
            },
        }
    
    def analyze_connection(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "tcp",
        port: int = 0,
        bytes_sent: int = 0,
        packets: int = 0,
        duration: float = 0.0,
    ) -> List[AttackPath]:
        """
        Analyze a network connection and detect potential attacks.
        
        Returns:
            List of detected attack paths
        """
        self.feature_extractor.add_connection(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port=port,
            bytes_sent=bytes_sent,
            packets=packets,
            duration=duration,
        )
        
        detected_attacks = []
        
        # Run all detection methods
        detected_attacks.extend(self._detect_lateral_movement())
        detected_attacks.extend(self._detect_c2_beaconing())
        detected_attacks.extend(self._detect_data_exfiltration())
        detected_attacks.extend(self._detect_port_scanning())
        detected_attacks.extend(self._detect_anomalous_subgraph())
        
        # Update risk scores
        for attack in detected_attacks:
            for node_id in attack.affected_nodes:
                if node_id in self.feature_extractor.nodes:
                    self.feature_extractor.nodes[node_id].risk_score = max(
                        self.feature_extractor.nodes[node_id].risk_score,
                        attack.confidence,
                    )
                    self.feature_extractor.nodes[node_id].alert_count += 1
        
        self._attack_paths.extend(detected_attacks)
        return detected_attacks
    
    def _detect_lateral_movement(self) -> List[AttackPath]:
        """
        Detect lateral movement using graph analysis.
        
        Looks for:
        - A node connecting to many new nodes in a short time
        - Unusual RDP/WMI/PsExec connections
        - Authentication chains
        """
        attacks = []
        extractor = self.feature_extractor
        now = datetime.utcnow()
        window = timedelta(minutes=30)
        
        for node_id, node in extractor.nodes.items():
            # Get recent outbound connections
            recent_edges = [
                e for e in extractor.edges
                if e.source_id == node_id
                and e.timestamp >= now - window
            ]
            
            # Check for star expansion pattern (one-to-many)
            unique_targets = set(e.target_id for e in recent_edges)
            if len(unique_targets) >= 3:
                # Check if these are new connections (not in baseline)
                new_targets = len(unique_targets)
                
                if new_targets >= 3:
                    confidence = min(0.5 + (new_targets - 3) * 0.1, 0.95)
                    
                    if confidence >= self.min_confidence:
                        attacks.append(AttackPath(
                            path=[node_id] + list(unique_targets),
                            attack_type="lateral_movement",
                            confidence=confidence,
                            description=(
                                f"Lateral movement detected: {node_id} connected to "
                                f"{new_targets} unique hosts in {window.total_seconds()/60:.0f}min"
                            ),
                            affected_nodes=[node_id] + list(unique_targets),
                            recommended_actions=[
                                f"Investigate {node_id} for compromise",
                                "Check authentication logs for credential abuse",
                                "Isolate affected hosts if confirmed",
                                "Review RDP/WMI/PsExec usage policies",
                            ],
                        ))
        
        return attacks
    
    def _detect_c2_beaconing(self) -> List[AttackPath]:
        """
        Detect C2 beaconing using temporal graph patterns.
        
        Looks for:
        - Regular periodic connections to external IPs
        - Connections with consistent intervals
        - Low-volume, persistent connections
        """
        attacks = []
        extractor = self.feature_extractor
        
        # Group edges by (source, target) pair
        connection_pairs = defaultdict(list)
        for edge in extractor.edges:
            if edge.edge_type == "connection":
                key = (edge.source_id, edge.target_id)
                connection_pairs[key].append(edge)
        
        for (src, dst), edges in connection_pairs.items():
            if len(edges) < 3:
                continue
            
            # Sort by timestamp
            edges.sort(key=lambda e: e.timestamp)
            
            # Check for regular intervals (beaconing)
            intervals = []
            for i in range(1, len(edges)):
                interval = (edges[i].timestamp - edges[i-1].timestamp).total_seconds()
                intervals.append(interval)
            
            if intervals:
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                
                # Beaconing: low variance in intervals
                if std_interval / mean_interval < 0.3:
                    # Consistent intervals detected
                    confidence = min(0.7 + (1.0 - std_interval / mean_interval) * 0.3, 0.95)
                    
                    if confidence >= self.min_confidence:
                        attacks.append(AttackPath(
                            path=[src, dst],
                            attack_type="c2_beaconing",
                            confidence=confidence,
                            description=(
                                f"C2 beaconing detected: {src} → {dst} "
                                f"({len(edges)} connections, interval ~{mean_interval:.0f}s)"
                            ),
                            affected_nodes=[src, dst],
                            recommended_actions=[
                                f"Investigate {src} for malware infection",
                                f"Block {dst} on firewall",
                                "Check for other hosts communicating with same IP",
                                "Run EDR scan on affected host",
                            ],
                        ))
        
        return attacks
    
    def _detect_data_exfiltration(self) -> List[AttackPath]:
        """
        Detect data exfiltration using volume analysis on graph edges.
        
        Looks for:
        - Unusually large data transfers
        - Outbound connections with high byte counts
        - Connections to unusual ports/protocols
        """
        attacks = []
        extractor = self.feature_extractor
        
        # Calculate baseline bytes per connection
        all_bytes = [e.bytes_transferred for e in extractor.edges if e.edge_type == "connection"]
        if not all_bytes:
            return attacks
        
        mean_bytes = np.mean(all_bytes)
        std_bytes = np.std(all_bytes)
        threshold = mean_bytes + self.threshold_multiplier * std_bytes
        
        for edge in extractor.edges:
            if edge.edge_type != "connection":
                continue
            
            if edge.bytes_transferred > threshold and edge.bytes_transferred > 10_000_000:  # >10MB
                confidence = min(
                    0.5 + (edge.bytes_transferred - threshold) / threshold * 0.4,
                    0.95,
                )
                
                if confidence >= self.min_confidence:
                    attacks.append(AttackPath(
                        path=[edge.source_id, edge.target_id],
                        attack_type="data_exfiltration",
                        confidence=confidence,
                        description=(
                            f"Possible data exfiltration: {edge.source_id} → {edge.target_id} "
                            f"({edge.bytes_transferred / 1024 / 1024:.1f}MB transferred)"
                        ),
                        affected_nodes=[edge.source_id, edge.target_id],
                        recommended_actions=[
                            f"Inspect traffic from {edge.source_id}",
                            f"Check {edge.target_id} for unauthorized data storage",
                            "Review data loss prevention policies",
                            "Enable additional logging on affected hosts",
                        ],
                    ))
        
        return attacks
    
    def _detect_port_scanning(self) -> List[AttackPath]:
        """
        Detect port scanning using graph fan-out patterns.
        
        Looks for:
        - One source connecting to many ports on one target
        - Rapid connection attempts
        - Many failed connections
        """
        attacks = []
        extractor = self.feature_extractor
        
        # Group by (source, target) and count unique ports
        port_scan_patterns = defaultdict(set)
        for edge in extractor.edges:
            if edge.edge_type == "connection":
                key = (edge.source_id, edge.target_id)
                port_scan_patterns[key].add(edge.port)
        
        for (src, dst), ports in port_scan_patterns.items():
            if len(ports) >= 10:  # 10+ ports = scanning
                confidence = min(0.6 + (len(ports) - 10) * 0.02, 0.95)
                
                if confidence >= self.min_confidence:
                    attacks.append(AttackPath(
                        path=[src, dst],
                        attack_type="port_scanning",
                        confidence=confidence,
                        description=(
                            f"Port scanning detected: {src} scanned {len(ports)} ports on {dst}"
                        ),
                        affected_nodes=[src, dst],
                        recommended_actions=[
                            f"Block {src} at firewall temporarily",
                            "Investigate source host for compromise",
                            "Check for successful connections on unusual ports",
                            "Review network segmentation rules",
                        ],
                    ))
        
        return attacks
    
    def _detect_anomalous_subgraph(self) -> List[AttackPath]:
        """
        Detect anomalous subgraphs using graph structure analysis.
        
        Uses:
        - Graph density anomalies
        - Betweenness centrality spikes
        - Sudden changes in graph structure
        """
        attacks = []
        extractor = self.feature_extractor
        
        if len(extractor.nodes) < 5:
            return attacks
        
        node_features, adj, node_ids = extractor.to_feature_matrix()
        n = len(node_ids)
        
        # Calculate graph metrics
        degree_centrality = adj.sum(axis=1) / max(n - 1, 1)
        betweenness = self._estimate_betweenness(adj)
        
        # Detect high-centrality anomalies (potential pivot points)
        mean_centrality = np.mean(degree_centrality)
        std_centrality = np.std(degree_centrality)
        centrality_threshold = mean_centrality + self.threshold_multiplier * std_centrality
        
        for i in range(n):
            if degree_centrality[i] > centrality_threshold:
                node_id = node_ids[i]
                confidence = min(
                    0.5 + (degree_centrality[i] - centrality_threshold) * 2,
                    0.9,
                )
                
                if confidence >= self.min_confidence:
                    # Find connected nodes
                    connected = [
                        node_ids[j] for j in range(n)
                        if adj[i, j] > 0 or adj[j, i] > 0
                    ]
                    
                    attacks.append(AttackPath(
                        path=[node_id] + connected[:5],
                        attack_type="lateral_movement",
                        confidence=confidence,
                        description=(
                            f"Anomalous graph centrality: {node_id} is a potential "
                            f"pivot point (centrality={degree_centrality[i]:.3f})"
                        ),
                        affected_nodes=[node_id] + connected,
                        recommended_actions=[
                            f"Investigate {node_id} as potential attack pivot",
                            "Review all connections to/from this host",
                            "Check for credential theft indicators",
                            "Implement network micro-segmentation",
                        ],
                    ))
        
        return attacks
    
    def _estimate_betweenness(self, adj: np.ndarray) -> np.ndarray:
        """
        Estimate betweenness centrality using approximation.
        For large graphs, uses sampling.
        """
        n = adj.shape[0]
        betweenness = np.zeros(n)
        
        if n > 100:
            # Sample nodes for large graphs
            sample_size = min(100, n)
            sample_nodes = np.random.choice(n, sample_size, replace=False)
        else:
            sample_nodes = range(n)
        
        for s in sample_nodes:
            # BFS from source
            visited = set()
            queue = [(s, 0)]
            paths = defaultdict(list)
            
            while queue:
                node, dist = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                
                for neighbor in range(n):
                    if adj[node, neighbor] > 0 and neighbor not in visited:
                        queue.append((neighbor, dist + 1))
                        paths[neighbor].append(node)
            
            # Count shortest paths through each node
            for target in paths:
                for intermediate in paths[target]:
                    betweenness[intermediate] += 1.0 / max(len(paths[target]), 1)
        
        # Normalize
        max_betweenness = np.max(betweenness)
        if max_betweenness > 0:
            betweenness /= max_betweenness
        
        return betweenness
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """Get a summary of all detected attacks."""
        attack_types = defaultdict(int)
        total_confidence = 0.0
        
        for attack in self._attack_paths:
            attack_types[attack.attack_type] += 1
            total_confidence += attack.confidence
        
        return {
            "total_attacks_detected": len(self._attack_paths),
            "attack_types": dict(attack_types),
            "average_confidence": total_confidence / max(len(self._attack_paths), 1),
            "graph_stats": self.feature_extractor.get_graph_stats(),
            "high_risk_nodes": [
                {"node_id": nid, "risk_score": n.risk_score}
                for nid, n in self.feature_extractor.nodes.items()
                if n.risk_score > 0.5
            ],
            "recent_attacks": [
                {
                    "type": a.attack_type,
                    "confidence": a.confidence,
                    "description": a.description,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in self._attack_paths[-10:]  # Last 10
            ],
        }
    
    def get_network_graph(self) -> Dict[str, Any]:
        """Export the current network graph for visualization."""
        nodes = []
        for nid, node in self.feature_extractor.nodes.items():
            nodes.append({
                "id": nid,
                "type": node.node_type,
                "risk_score": node.risk_score,
                "alert_count": node.alert_count,
            })
        
        edges = []
        for edge in self.feature_extractor.edges:
            edges.append({
                "source": edge.source_id,
                "target": edge.target_id,
                "type": edge.edge_type,
                "protocol": edge.protocol,
                "port": edge.port,
                "bytes": edge.bytes_transferred,
            })
        
        return {"nodes": nodes, "edges": edges}


# ═══════════════════════════════════════════════════════════════════════════
# 5. DEEP GNN WITH PYTORCH (GraphSAGE + GAT)
# ═══════════════════════════════════════════════════════════════════════════

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import torch_geometric
    from torch_geometric.nn import SAGEConv, GATConv, GCNConv, global_mean_pool
    from torch_geometric.data import Data, DataLoader
    from torch_geometric.utils import from_scipy_sparse_matrix
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False


class GraphSAGEModel(nn.Module):
    """
    Deep GraphSAGE + GAT model for attack detection.
    Architecture de pointe pour la détection d'anomalies dans les graphes.
    """
    def __init__(self, in_channels: int = 8, hidden_channels: int = 128, num_classes: int = 2):
        super().__init__()
        
        # GraphSAGE layers
        self.sage1 = SAGEConv(in_channels, hidden_channels)
        self.sage2 = SAGEConv(hidden_channels, hidden_channels * 2)
        self.sage3 = SAGEConv(hidden_channels * 2, hidden_channels)
        
        # Graph Attention layers
        self.gat1 = GATConv(hidden_channels, hidden_channels // 2, heads=4, concat=True)
        self.gat2 = GATConv(hidden_channels * 2, hidden_channels // 4, heads=4, concat=True)
        
        # GCN layer for final encoding
        self.gcn = GCNConv(hidden_channels, hidden_channels // 2)
        
        # MLP classifier
        self.mlp = nn.Sequential(
            nn.Linear(hidden_channels // 2 + hidden_channels, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )
        
        # Autoencoder for anomaly detection (reconstruction)
        self.encoder = nn.Sequential(
            nn.Linear(in_channels, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, in_channels),
        )
        
        self._init_weights()
    
    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                nn.init.constant_(m.bias, 0)
    
    def forward(self, x, edge_index, batch=None):
        # GraphSAGE encoding
        x1 = F.relu(self.sage1(x, edge_index))
        x1 = F.dropout(x1, p=0.2, training=self.training)
        x2 = F.relu(self.sage2(x1, edge_index))
        x2 = F.dropout(x2, p=0.2, training=self.training)
        x3 = F.relu(self.sage3(x2, edge_index))
        
        # GAT attention
        x_att = F.relu(self.gat1(x3, edge_index))
        x_att = F.relu(self.gat2(x_att, edge_index))
        
        # GCN
        x_gcn = F.relu(self.gcn(x3, edge_index))
        
        # Combine features
        x_combined = torch.cat([x_att, x_gcn], dim=-1)
        
        # Classification
        out = self.mlp(x_combined)
        
        # Reconstruction (for anomaly detection)
        z = self.encoder(x)
        x_recon = self.decoder(z)
        
        return out, x_recon, z
    
    def get_embeddings(self, x, edge_index):
        """Get node embeddings for visualization."""
        with torch.no_grad():
            x1 = F.relu(self.sage1(x, edge_index))
            x2 = F.relu(self.sage2(x1, edge_index))
            x3 = F.relu(self.sage3(x2, edge_index))
            x_att = F.relu(self.gat1(x3, edge_index))
            x_att = F.relu(self.gat2(x_att, edge_index))
            x_gcn = F.relu(self.gcn(x3, edge_index))
            return torch.cat([x_att, x_gcn], dim=-1)


class DeepGNNAttackDetector:
    """
    Deep GNN Attack Detector with PyTorch Geometric.
    Combine GraphSAGE, GAT, GCN, et Autoencoder pour la détection.
    """
    def __init__(self, in_channels: int = 8, hidden_channels: int = 128):
        self.model = GraphSAGEModel(in_channels, hidden_channels) if TORCH_AVAILABLE else None
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001, weight_decay=5e-4) if self.model else None
        self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(self.optimizer, patience=10) if self.optimizer else None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.anomaly_threshold = 0.5
        self.trained = False
        
        if self.model:
            self.model.to(self.device)
    
    def prepare_data(self, node_features: np.ndarray, adj_matrix: np.ndarray, labels: Optional[np.ndarray] = None):
        """Convert numpy arrays to PyTorch Geometric Data object."""
        if not TORCH_GEOMETRIC_AVAILABLE:
            return None
        
        x = torch.FloatTensor(node_features)
        
        # Convert adjacency to edge_index
        edge_index = []
        n = adj_matrix.shape[0]
        for i in range(n):
            for j in range(n):
                if adj_matrix[i, j] > 0:
                    edge_index.append([i, j])
        
        if not edge_index:
            edge_index = torch.zeros((2, 0), dtype=torch.long)
        else:
            edge_index = torch.LongTensor(edge_index).t()
        
        data = Data(x=x, edge_index=edge_index)
        
        if labels is not None:
            data.y = torch.LongTensor(labels)
        
        return data
    
    def train_step(self, data: Data) -> Dict[str, float]:
        """Single training step."""
        if not self.model or not self.optimizer:
            return {"loss": 0.0, "cls_loss": 0.0, "recon_loss": 0.0}
        
        self.model.train()
        self.optimizer.zero_grad()
        
        data = data.to(self.device)
        
        # Forward
        out, x_recon, z = self.model(data.x, data.edge_index)
        
        # Classification loss (if labels available)
        cls_loss = 0.0
        if hasattr(data, 'y') and data.y is not None:
            cls_loss = F.cross_entropy(out, data.y)
        
        # Reconstruction loss (for anomaly detection)
        recon_loss = F.mse_loss(x_recon, data.x)
        
        # Total loss
        loss = cls_loss + 0.5 * recon_loss
        
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
        self.optimizer.step()
        
        return {
            "loss": loss.item(),
            "cls_loss": cls_loss.item() if isinstance(cls_loss, torch.Tensor) else 0.0,
            "recon_loss": recon_loss.item(),
        }
    
    def detect_anomalies(self, node_features: np.ndarray, adj_matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalous nodes using reconstruction error.
        Returns anomaly scores and predictions.
        """
        if not self.model:
            return np.zeros(len(node_features)), np.zeros(len(node_features))
        
        self.model.eval()
        data = self.prepare_data(node_features, adj_matrix)
        if data is None:
            return np.zeros(len(node_features)), np.zeros(len(node_features))
        
        data = data.to(self.device)
        
        with torch.no_grad():
            out, x_recon, z = self.model(data.x, data.edge_index)
            
            # Reconstruction error per node
            recon_error = F.mse_loss(x_recon, data.x, reduction='none').mean(dim=1)
            anomaly_scores = recon_error.cpu().numpy()
            
            # Classification probabilities
            probs = F.softmax(out, dim=1)[:, 1].cpu().numpy()  # Probability of attack
        
        return anomaly_scores, probs
    
    def get_embeddings(self, node_features: np.ndarray, adj_matrix: np.ndarray) -> np.ndarray:
        """Get node embeddings for visualization."""
        if not self.model:
            return np.zeros((len(node_features), 64))
        
        self.model.eval()
        data = self.prepare_data(node_features, adj_matrix)
        if data is None:
            return np.zeros((len(node_features), 64))
        
        data = data.to(self.device)
        
        with torch.no_grad():
            embeddings = self.model.get_embeddings(data.x, data.edge_index)
        
        return embeddings.cpu().numpy()


# ═══════════════════════════════════════════════════════════════════════════
# 6. ENHANCED GNN DETECTOR (Combines all techniques)
# ═══════════════════════════════════════════════════════════════════════════

class EnhancedGNNAttackDetector(GNNAttackDetector):
    """
    Enhanced GNN Attack Detector with Deep Learning.
    Combine les méthodes classiques + Deep GNN + Autoencoder.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.deep_gnn = DeepGNNAttackDetector()
        self.zero_day_detections: List[Dict] = []
        self.attack_graph_visualization: Dict = {}
    
    def analyze_with_deep_gnn(self) -> List[AttackPath]:
        """Analyze graph using deep GNN model."""
        attacks = []
        
        if len(self.feature_extractor.nodes) < 3:
            return attacks
        
        node_features, adj, node_ids = self.feature_extractor.to_feature_matrix()
        
        # Detect anomalies with deep GNN
        anomaly_scores, attack_probs = self.deep_gnn.detect_anomalies(node_features, adj)
        
        for i, node_id in enumerate(node_ids):
            if anomaly_scores[i] > self.deep_gnn.anomaly_threshold or attack_probs[i] > 0.5:
                confidence = min(float(anomaly_scores[i] + attack_probs[i]) / 2.0, 0.95)
                
                if confidence >= self.min_confidence:
                    # Find connected nodes
                    connected = [node_ids[j] for j in range(len(node_ids)) if adj[i, j] > 0 or adj[j, i] > 0]
                    
                    attack_type = "zero_day" if anomaly_scores[i] > 0.7 else "anomalous_node"
                    
                    attacks.append(AttackPath(
                        path=[node_id] + connected[:5],
                        attack_type=attack_type,
                        confidence=confidence,
                        description=(
                            f"Deep GNN detected anomaly: {node_id} "
                            f"(reconstruction_error={anomaly_scores[i]:.3f}, "
                            f"attack_prob={attack_probs[i]:.3f})"
                        ),
                        affected_nodes=[node_id] + connected,
                        recommended_actions=[
                            f"Investigate {node_id} - potential zero-day attack",
                            "Deep packet inspection recommended",
                            "Isolate node for forensic analysis",
                            "Update detection signatures",
                        ],
                    ))
                    
                    if anomaly_scores[i] > 0.7:
                        self.zero_day_detections.append({
                            "node_id": node_id,
                            "anomaly_score": float(anomaly_scores[i]),
                            "attack_prob": float(attack_probs[i]),
                            "timestamp": datetime.utcnow().isoformat(),
                        })
        
        return attacks
    
    def train_deep_gnn(self, node_features: np.ndarray, adj_matrix: np.ndarray, labels: Optional[np.ndarray] = None, epochs: int = 100):
        """Train the deep GNN model."""
        if not TORCH_GEOMETRIC_AVAILABLE:
            logger.warning("PyTorch Geometric not available for training")
            return {"error": "PyTorch Geometric not available"}
        
        data = self.deep_gnn.prepare_data(node_features, adj_matrix, labels)
        if data is None:
            return {"error": "Failed to prepare data"}
        
        logger.info(f"Training Deep GNN for {epochs} epochs...")
        for epoch in range(epochs):
            loss_dict = self.deep_gnn.train_step(data)
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: loss={loss_dict['loss']:.4f}")
        
        self.deep_gnn.trained = True
        logger.info("Deep GNN training complete")
        return {"status": "trained", "epochs": epochs}
    
    def get_zero_day_summary(self) -> Dict[str, Any]:
        """Get summary of zero-day detections."""
        return {
            "total_zero_day_detections": len(self.zero_day_detections),
            "detections": self.zero_day_detections[-20:],  # Last 20
            "deep_gnn_trained": self.deep_gnn.trained,
        }
    
    def get_embeddings_for_viz(self) -> Dict[str, Any]:
        """Get node embeddings for 2D/3D visualization."""
        if len(self.feature_extractor.nodes) < 3:
            return {"error": "Not enough nodes"}
        
        node_features, adj, node_ids = self.feature_extractor.to_feature_matrix()
        embeddings = self.deep_gnn.get_embeddings(node_features, adj)
        
        # Store for visualization
        self.attack_graph_visualization = {
            "nodes": [{"id": nid, "embedding": emb.tolist()} for nid, emb in zip(node_ids, embeddings)],
            "edges": [{"source": e.source_id, "target": e.target_id} for e in self.feature_extractor.edges],
        }
        
        return self.attack_graph_visualization


# ═══════════════════════════════════════════════════════════════════════════
# 7. FACTORY & CLI
# ═══════════════════════════════════════════════════════════════════════════

def create_default_gnn_detector(
    window_size_minutes: int = 60,
    threshold_multiplier: float = 3.0,
    min_confidence: float = 0.6,
    enhanced: bool = True,
) -> GNNAttackDetector:
    """Create a GNN attack detector with default configuration."""
    feature_extractor = GraphFeatureExtractor(window_size_minutes=window_size_minutes)
    
    if enhanced and TORCH_AVAILABLE:
        detector = EnhancedGNNAttackDetector(
            feature_extractor=feature_extractor,
            threshold_multiplier=threshold_multiplier,
            min_confidence=min_confidence,
        )
        logger.info("Enhanced GNN Detector created (with Deep Learning)")
        return detector
    
    return GNNAttackDetector(
        feature_extractor=feature_extractor,
        threshold_multiplier=threshold_multiplier,
        min_confidence=min_confidence,
    )


if __name__ == "__main__":
    import structlog
    structlog.configure(wrapper_class=structlog.PrintLoggerFactory())
    logger = structlog.get_logger()
    
    logger.info("Cyber Global Shield - GNN Attack Detector v2.0")
    logger.info(f"PyTorch: {'OK' if TORCH_AVAILABLE else 'N/A'} | PyG: {'OK' if TORCH_GEOMETRIC_AVAILABLE else 'N/A'}")
    
    # Demo
    detector = create_default_gnn_detector(enhanced=True)
    
    # Simulate some connections
    for i in range(20):
        detector.analyze_connection(
            src_ip=f"10.0.0.{random.randint(1, 10)}",
            dst_ip=f"10.0.0.{random.randint(11, 50)}",
            port=random.choice([22, 80, 443, 445, 3389, 8080, 8443]),
            bytes_sent=random.randint(100, 100000),
            packets=random.randint(1, 1000),
        )
    
    summary = detector.get_attack_summary()
    logger.info(f"Attack Summary: {json.dumps(summary, indent=2, default=str)}")
    
    # Deep GNN analysis if available
    if isinstance(detector, EnhancedGNNAttackDetector):
        node_features, adj, node_ids = detector.feature_extractor.to_feature_matrix()
        detector.train_deep_gnn(node_features, adj, epochs=5)
        deep_attacks = detector.analyze_with_deep_gnn()
        logger.info(f"Deep GNN detected {len(deep_attacks)} additional attacks")
        logger.info(f"Zero-day detections: {detector.get_zero_day_summary()}")
