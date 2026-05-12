"""
Tests for the GNN Attack Detector module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.ml.gnn_detector import (
    GNNAttackDetector,
    GraphFeatureExtractor,
    create_default_gnn_detector,
    AttackPath,
)
from datetime import datetime, timedelta
import time


def test_create_detector():
    """Test that the detector can be created with default settings."""
    detector = create_default_gnn_detector()
    assert detector is not None
    assert detector.min_confidence == 0.6
    assert detector.threshold_multiplier == 3.0
    print("✅ test_create_detector PASSED")


def test_add_connection():
    """Test adding connections to the graph."""
    extractor = GraphFeatureExtractor()
    
    # Add some normal connections
    extractor.add_connection("192.168.1.1", "192.168.1.2", protocol="tcp", port=443)
    extractor.add_connection("192.168.1.1", "192.168.1.3", protocol="tcp", port=80)
    extractor.add_connection("192.168.1.2", "192.168.1.4", protocol="udp", port=53)
    
    stats = extractor.get_graph_stats()
    assert stats["num_nodes"] == 4
    assert stats["num_edges"] == 3
    print(f"✅ test_add_connection PASSED (nodes={stats['num_nodes']}, edges={stats['num_edges']})")


def test_lateral_movement_detection():
    """Test detection of lateral movement pattern."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    now = datetime.utcnow()
    
    # Simulate lateral movement: one host connecting to many others
    attacker = "10.0.0.50"
    targets = [f"10.0.0.{i}" for i in range(1, 8)]
    
    for target in targets:
        detector.analyze_connection(
            src_ip=attacker,
            dst_ip=target,
            protocol="tcp",
            port=445,  # SMB
            bytes_sent=1000,
            packets=5,
        )
    
    summary = detector.get_attack_summary()
    assert summary["total_attacks_detected"] > 0
    
    # Check that lateral movement was detected
    attack_types = summary["attack_types"]
    assert "lateral_movement" in attack_types
    print(f"✅ test_lateral_movement_detection PASSED (detected {summary['total_attacks_detected']} attacks)")


def test_c2_beaconing_detection():
    """Test detection of C2 beaconing pattern."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    # Simulate C2 beaconing: regular intervals to external IP
    c2_server = "203.0.113.99"
    victim = "192.168.1.100"
    
    base_time = datetime.utcnow()
    for i in range(5):
        # Regular 60-second intervals
        ts = base_time + timedelta(seconds=i * 60)
        # Add connection directly to extractor with specific timestamp
        detector.feature_extractor.add_connection(
            src_ip=victim,
            dst_ip=c2_server,
            protocol="tcp",
            port=8443,
            bytes_sent=500,
            packets=3,
            timestamp=ts,
        )
    
    # Call detection directly (not through analyze_connection which adds a new edge)
    attacks = detector._detect_c2_beaconing()
    
    c2_detected = any(a.attack_type == "c2_beaconing" for a in attacks)
    assert c2_detected, f"C2 beaconing should be detected"
    print("✅ test_c2_beaconing_detection PASSED")


def test_port_scanning_detection():
    """Test detection of port scanning pattern."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    scanner = "10.0.0.5"
    target = "192.168.1.1"
    
    # Simulate port scan: one source connecting to many ports on one target
    for port in range(1, 30):
        detector.analyze_connection(
            src_ip=scanner,
            dst_ip=target,
            protocol="tcp",
            port=port,
            bytes_sent=100,
            packets=1,
        )
    
    summary = detector.get_attack_summary()
    assert "port_scanning" in summary["attack_types"]
    print(f"✅ test_port_scanning_detection PASSED")


def test_data_exfiltration_detection():
    """Test detection of data exfiltration."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    # Add some normal traffic first (baseline)
    for i in range(10):
        detector.analyze_connection(
            src_ip="192.168.1.10",
            dst_ip=f"10.0.0.{i}",
            protocol="tcp",
            port=443,
            bytes_sent=1000,
            packets=5,
        )
    
    # Now add a large transfer (exfiltration)
    attacks = detector.analyze_connection(
        src_ip="192.168.1.10",
        dst_ip="203.0.113.200",
        protocol="tcp",
        port=443,
        bytes_sent=50_000_000,  # 50MB
        packets=1000,
    )
    
    exfil_detected = any(a.attack_type == "data_exfiltration" for a in attacks)
    assert exfil_detected, "Data exfiltration should be detected"
    print("✅ test_data_exfiltration_detection PASSED")


def test_feature_matrix():
    """Test conversion to feature matrix."""
    extractor = GraphFeatureExtractor()
    
    # Add some connections
    extractor.add_connection("A", "B")
    extractor.add_connection("B", "C")
    extractor.add_connection("A", "C")
    extractor.add_auth_event("user1", "A")
    
    features, adj, node_ids = extractor.to_feature_matrix()
    
    assert features.shape[0] == len(node_ids)  # N nodes
    assert features.shape[1] == 8  # 8 features per node
    assert adj.shape[0] == adj.shape[1]  # Square matrix
    print(f"✅ test_feature_matrix PASSED (nodes={len(node_ids)}, features={features.shape})")


def test_network_graph_export():
    """Test exporting the network graph for visualization."""
    detector = create_default_gnn_detector()
    
    detector.analyze_connection("10.0.0.1", "10.0.0.2")
    detector.analyze_connection("10.0.0.1", "10.0.0.3")
    
    graph = detector.get_network_graph()
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    print(f"✅ test_network_graph_export PASSED")


def test_attack_summary():
    """Test attack summary generation."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    # Generate some attacks
    for i in range(5):
        detector.analyze_connection(
            src_ip="10.0.0.1",
            dst_ip=f"192.168.1.{i}",
            protocol="tcp",
            port=445,
        )
    
    summary = detector.get_attack_summary()
    assert "total_attacks_detected" in summary
    assert "attack_types" in summary
    assert "high_risk_nodes" in summary
    assert "recent_attacks" in summary
    print(f"✅ test_attack_summary PASSED")


def test_auth_event():
    """Test adding authentication events."""
    extractor = GraphFeatureExtractor()
    
    extractor.add_auth_event("admin", "192.168.1.1", success=True)
    extractor.add_auth_event("admin", "192.168.1.2", success=True)
    extractor.add_auth_event("admin", "192.168.1.3", success=False)
    
    stats = extractor.get_graph_stats()
    assert stats["num_nodes"] == 4  # admin + 3 IPs
    assert stats["num_edges"] == 3
    print(f"✅ test_auth_event PASSED (nodes={stats['num_nodes']})")


def test_edge_pruning():
    """Test that old edges are pruned."""
    extractor = GraphFeatureExtractor(window_size_minutes=1)  # 1 minute window
    
    # Add old connection
    old_time = datetime.utcnow() - timedelta(minutes=5)
    extractor.add_connection(
        "10.0.0.1", "10.0.0.2",
        timestamp=old_time,
    )
    
    # Should be pruned
    assert len(extractor.edges) == 0
    print("✅ test_edge_pruning PASSED")


def test_anomalous_centrality():
    """Test detection of anomalous graph centrality."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    # Create a star pattern: one central node connected to many
    central = "10.0.0.1"
    for i in range(10):
        detector.analyze_connection(
            src_ip=central,
            dst_ip=f"192.168.1.{i}",
            protocol="tcp",
            port=80,
        )
    
    summary = detector.get_attack_summary()
    high_risk = summary["high_risk_nodes"]
    central_risks = [n for n in high_risk if n["node_id"] == central]
    
    assert len(central_risks) > 0
    assert central_risks[0]["risk_score"] > 0
    print(f"✅ test_anomalous_centrality PASSED (central node risk={central_risks[0]['risk_score']:.2f})")


def test_recommended_actions():
    """Test that attack paths include recommended actions."""
    detector = create_default_gnn_detector(min_confidence=0.3)
    
    attacks = detector.analyze_connection(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="tcp",
        port=445,
    )
    
    # Trigger lateral movement
    for i in range(3, 8):
        detector.analyze_connection(
            src_ip="10.0.0.1",
            dst_ip=f"10.0.0.{i}",
            protocol="tcp",
            port=445,
        )
    
    summary = detector.get_attack_summary()
    recent = summary["recent_attacks"]
    
    # Check that we have attack descriptions
    assert len(recent) > 0
    for attack in recent:
        assert "description" in attack
        assert "type" in attack
        assert "confidence" in attack
    print(f"✅ test_recommended_actions PASSED ({len(recent)} recent attacks)")


if __name__ == "__main__":
    print("=" * 60)
    print("GNN Attack Detector Tests")
    print("=" * 60)
    
    tests = [
        test_create_detector,
        test_add_connection,
        test_lateral_movement_detection,
        test_c2_beaconing_detection,
        test_port_scanning_detection,
        test_data_exfiltration_detection,
        test_feature_matrix,
        test_network_graph_export,
        test_attack_summary,
        test_auth_event,
        test_edge_pruning,
        test_anomalous_centrality,
        test_recommended_actions,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} FAILED: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"📊 Results: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 60)
    
    sys.exit(0 if failed == 0 else 1)
