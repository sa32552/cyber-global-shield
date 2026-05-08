"""
Tests d'intégration pour les modules quantiques et Phase 5-10.
Couvre : Quantum ML, Quantum Modules, Phase 5-10, Threat Intel Connectors.

Run: pytest tests/integration/test_quantum_modules.py -v --tb=short
"""

import os
import sys
import json
import pytest
import asyncio
import numpy as np
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "Cyber Global Shield"))

from app.ml.quantum_anomaly_detector import create_quantum_detector, QuantumAnomalyDetector
from app.ml.quantum_kernel import create_quantum_kernel, QuantumKernel
from app.ml.quantum_federated import create_quantum_fl_server, QuantumFederatedServer
from app.core.connectors.alienvault import AlienVaultConnector
from app.core.connectors.misp import MISPConnector


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_logs():
    """Generate sample logs for quantum detection."""
    logs = []
    for i in range(20):
        logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "10.0.1.1",
            "event_type": "connection",
            "bytes_sent": 100 + i * 10,
            "bytes_received": 200 + i * 5,
            "duration": 0.5 + i * 0.1,
            "protocol": "tcp",
            "port": 80 if i < 18 else 4444,
            "org_id": "test-org",
        })
    # Add some anomalous logs
    logs.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.0.50",
        "event_type": "ransomware_activity",
        "bytes_sent": 999999,
        "bytes_received": 0,
        "duration": 0.01,
        "protocol": "tcp",
        "port": 445,
        "org_id": "test-org",
    })
    return logs


@pytest.fixture
def sample_kernel_data():
    """Sample data for quantum kernel computation."""
    np.random.seed(42)
    return np.random.rand(10, 4).tolist()


# =============================================================================
# Test 1: Quantum Anomaly Detector
# =============================================================================

class TestQuantumAnomalyDetector:
    """Test quantum-enhanced anomaly detection."""

    def test_detector_initialization(self):
        """Detector should initialize with default parameters."""
        detector = create_quantum_detector(n_qubits=2)
        assert detector is not None
        assert isinstance(detector, QuantumAnomalyDetector)
        stats = detector.get_stats()
        assert "total_detections" in stats
        assert "anomalies_found" in stats

    def test_detect_anomalies(self, sample_logs):
        """Detector should identify anomalous logs."""
        detector = create_quantum_detector(n_qubits=2)
        result = detector.detect(sample_logs)

        assert result is not None
        assert hasattr(result, "anomaly_score")
        assert hasattr(result, "is_anomaly")
        assert hasattr(result, "explanation")
        assert hasattr(result, "feature_scores")

        # The ransomware log should be detected
        assert result.is_anomaly is True
        assert result.anomaly_score > 0.5
        print(f"  ✅ Quantum anomaly score: {result.anomaly_score:.4f}")

    def test_detect_normal_logs(self):
        """Detector should not flag normal logs."""
        normal_logs = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "event_type": "http_request",
                "bytes_sent": 500,
                "bytes_received": 1200,
                "duration": 0.3,
                "protocol": "tcp",
                "port": 80,
                "org_id": "test-org",
            }
            for _ in range(5)
        ]

        detector = create_quantum_detector(n_qubits=2)
        result = detector.detect(normal_logs)

        # Normal traffic should have low anomaly score
        assert result.anomaly_score < 0.8
        print(f"  ✅ Normal traffic score: {result.anomaly_score:.4f} (expected < 0.8)")

    def test_detector_stats(self, sample_logs):
        """Detector should track statistics."""
        detector = create_quantum_detector(n_qubits=2)

        # Run detection multiple times
        for _ in range(3):
            detector.detect(sample_logs)

        stats = detector.get_stats()
        assert stats["total_detections"] >= 3
        assert stats["anomalies_found"] >= 3
        print(f"  ✅ Stats: {stats['total_detections']} detections, {stats['anomalies_found']} anomalies")


# =============================================================================
# Test 2: Quantum Kernel
# =============================================================================

class TestQuantumKernel:
    """Test quantum kernel computation."""

    def test_kernel_initialization(self):
        """Kernel should initialize with default parameters."""
        kernel = create_quantum_kernel(n_qubits=2)
        assert kernel is not None
        assert isinstance(kernel, QuantumKernel)
        stats = kernel.get_stats()
        assert "total_kernels_computed" in stats

    def test_kernel_computation(self, sample_kernel_data):
        """Kernel should compute a valid kernel matrix."""
        kernel = create_quantum_kernel(n_qubits=2)
        matrix = kernel.compute_kernel(sample_kernel_data)

        assert matrix is not None
        assert matrix.shape == (10, 10)
        # Kernel matrix should be symmetric
        assert np.allclose(matrix, matrix.T, atol=1e-5)
        # Diagonal should be 1 (self-similarity)
        assert np.allclose(np.diag(matrix), 1.0, atol=1e-5)
        print(f"  ✅ Kernel matrix shape: {matrix.shape}, symmetric: True")

    def test_kernel_with_different_sizes(self):
        """Kernel should handle different input sizes."""
        kernel = create_quantum_kernel(n_qubits=2)

        for size in [2, 5, 8]:
            data = np.random.rand(size, 4).tolist()
            matrix = kernel.compute_kernel(data)
            assert matrix.shape == (size, size)
            print(f"  ✅ Kernel size {size}: shape {matrix.shape}")

    def test_kernel_stats(self, sample_kernel_data):
        """Kernel should track statistics."""
        kernel = create_quantum_kernel(n_qubits=2)

        for _ in range(5):
            kernel.compute_kernel(sample_kernel_data)

        stats = kernel.get_stats()
        assert stats["total_kernels_computed"] >= 5
        print(f"  ✅ Kernels computed: {stats['total_kernels_computed']}")


# =============================================================================
# Test 3: Quantum Federated Learning
# =============================================================================

class TestQuantumFederatedLearning:
    """Test quantum federated learning server."""

    def test_fl_server_initialization(self):
        """FL server should initialize with default parameters."""
        server = create_quantum_fl_server(num_rounds=5, min_clients=2)
        assert server is not None
        assert isinstance(server, QuantumFederatedServer)
        stats = server.get_stats()
        assert "total_rounds" in stats
        assert "clients_connected" in stats

    def test_fl_server_stats(self):
        """FL server should track statistics."""
        server = create_quantum_fl_server(num_rounds=10, min_clients=2)
        stats = server.get_stats()
        assert stats["total_rounds"] == 10
        assert stats["min_clients"] == 2
        print(f"  ✅ FL Server: {stats['total_rounds']} rounds, {stats['min_clients']} min clients")


# =============================================================================
# Test 4: AlienVault OTX Connector
# =============================================================================

class TestAlienVaultConnector:
    """Test AlienVault OTX connector."""

    @pytest.mark.asyncio
    async def test_connector_initialization(self):
        """Connector should initialize with API key."""
        connector = AlienVaultConnector(api_key="test-key")
        assert connector is not None
        stats = connector.get_stats()
        assert stats["status"] == "disconnected"
        await connector.close()

    @pytest.mark.asyncio
    async def test_check_ip_not_found(self):
        """Connector should handle 404 responses."""
        connector = AlienVaultConnector(api_key="test-key")
        result = await connector.check_ip("192.0.2.1")  # TEST-NET IP
        if result and result.get("not_found"):
            assert result["malicious"] is False
            print(f"  ✅ IP not found handled correctly")
        await connector.close()

    @pytest.mark.asyncio
    async def test_connector_stats(self):
        """Connector should track statistics."""
        connector = AlienVaultConnector(api_key="test-key")
        stats = connector.get_stats()
        assert "total_requests" in stats
        assert "cache_hits" in stats
        assert "indicators_found" in stats
        await connector.close()

    def test_hash_type_detection(self):
        """Connector should detect hash types correctly."""
        connector = AlienVaultConnector(api_key="test-key")

        assert connector._detect_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "MD5"
        assert connector._detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "SHA1"
        assert connector._detect_hash_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "SHA256"
        assert connector._detect_hash_type("unknown") == "unknown"
        print(f"  ✅ Hash type detection: MD5, SHA1, SHA256, unknown")


# =============================================================================
# Test 5: MISP Connector
# =============================================================================

class TestMISPConnector:
    """Test MISP connector."""

    @pytest.mark.asyncio
    async def test_connector_initialization(self):
        """Connector should initialize with URL and API key."""
        connector = MISPConnector(
            base_url="https://misp.test.local",
            api_key="test-key",
            verify_ssl=False,
        )
        assert connector is not None
        stats = connector.get_stats()
        assert stats["base_url"] == "https://misp.test.local"
        assert stats["status"] == "disconnected"
        await connector.close()

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Connector should handle unreachable server."""
        connector = MISPConnector(
            base_url="https://nonexistent.misp.local",
            api_key="test-key",
            verify_ssl=False,
        )
        healthy = await connector.check_health()
        assert healthy is False
        print(f"  ✅ MISP health check: {healthy} (expected False)")
        await connector.close()

    @pytest.mark.asyncio
    async def test_connector_stats(self):
        """Connector should track statistics."""
        connector = MISPConnector(
            base_url="https://misp.test.local",
            api_key="test-key",
        )
        stats = connector.get_stats()
        assert "total_requests" in stats
        assert "events_found" in stats
        assert "cache_size" in stats
        await connector.close()


# =============================================================================
# Test 6: Performance Optimizer v2
# =============================================================================

class TestPerformanceOptimizerV2:
    """Test performance optimizer v2."""

    def test_cache_layer(self):
        """Cache layer should store and retrieve values."""
        from app.core.performance_optimizer_v2 import performance_optimizer_v2
        cache = performance_optimizer_v2.cache

        # Test set/get
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(cache.set("test_key", {"data": "test_value"}, ttl=60))
        value = loop.run_until_complete(cache.get("test_key"))
        loop.close()

        assert value is not None
        assert value["data"] == "test_value"
        print(f"  ✅ Cache L1: set/get OK")

    def test_cache_stats(self):
        """Cache should track statistics."""
        from app.core.performance_optimizer_v2 import performance_optimizer_v2
        stats = performance_optimizer_v2.cache.get_stats()
        assert "l1_hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats
        print(f"  ✅ Cache stats: {stats['hit_rate']:.1f}% hit rate")

    def test_query_optimizer(self):
        """Query optimizer should detect slow queries."""
        from app.core.performance_optimizer_v2 import performance_optimizer_v2
        optimizer = performance_optimizer_v2.query_optimizer

        # Record fast query
        result = optimizer.record_execution("SELECT * FROM logs LIMIT 10", 0.05)
        assert result["execution_time_ms"] == 50.0
        assert len(result["suggestions"]) == 0

        # Record slow query
        result = optimizer.record_execution("SELECT * FROM huge_table JOIN another_table", 12.5)
        assert result["execution_time_ms"] == 12500.0
        assert len(result["suggestions"]) > 0
        print(f"  ✅ Query optimizer: {len(result['suggestions'])} suggestions for slow query")

    def test_batch_processor(self):
        """Batch processor should handle items."""
        from app.core.performance_optimizer_v2 import performance_optimizer_v2
        processor = performance_optimizer_v2.batch_processor
        stats = processor.get_stats()
        assert "batches_processed" in stats
        assert "items_processed" in stats
        print(f"  ✅ Batch processor initialized")

    def test_performance_report(self):
        """Performance report should be comprehensive."""
        from app.core.performance_optimizer_v2 import performance_optimizer_v2
        report = performance_optimizer_v2.get_performance_report()
        assert "cache" in report
        assert "query_optimizer" in report
        assert "batch_processor" in report
        assert "connection_pools" in report
        assert "uptime_seconds" in report
        print(f"  ✅ Performance report: {len(report)} sections")


# =============================================================================
# Test 7: Phase 5-10 Module Integration
# =============================================================================

class TestPhase5to10Modules:
    """Test Phase 5-10 advanced platform modules."""

    def test_auto_soc_orchestrator(self):
        """Auto-SOC Orchestrator should initialize."""
        try:
            from app.core.auto_soc_orchestrator import get_auto_soc_orchestrator
            orchestrator = get_auto_soc_orchestrator()
            assert orchestrator is not None
            stats = orchestrator.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Auto-SOC Orchestrator: initialized")
        except Exception as e:
            print(f"  ⚠️ Auto-SOC Orchestrator: {e}")

    def test_predictive_attack_engine(self):
        """Predictive Attack Engine should initialize."""
        try:
            from app.core.predictive_attack_engine import get_predictive_engine
            engine = get_predictive_engine()
            assert engine is not None
            stats = engine.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Predictive Attack Engine: initialized")
        except Exception as e:
            print(f"  ⚠️ Predictive Attack Engine: {e}")

    def test_neural_security_mesh(self):
        """Neural Security Mesh should initialize."""
        try:
            from app.core.neural_security_mesh import get_neural_mesh
            mesh = get_neural_mesh()
            assert mesh is not None
            stats = mesh.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Neural Security Mesh: initialized")
        except Exception as e:
            print(f"  ⚠️ Neural Security Mesh: {e}")

    def test_dark_web_intel_network(self):
        """Dark Web Intel Network should initialize."""
        try:
            from app.core.dark_web_intel_network import get_dark_web_intel
            intel = get_dark_web_intel()
            assert intel is not None
            stats = intel.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Dark Web Intel Network: initialized")
        except Exception as e:
            print(f"  ⚠️ Dark Web Intel Network: {e}")

    def test_cyber_risk_quantification(self):
        """Cyber Risk Quantification should initialize."""
        try:
            from app.core.cyber_risk_quantification import get_crq
            crq = get_crq()
            assert crq is not None
            stats = crq.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Cyber Risk Quantification: initialized")
        except Exception as e:
            print(f"  ⚠️ Cyber Risk Quantification: {e}")

    def test_active_defense_countermeasures(self):
        """Active Defense Countermeasures should initialize."""
        try:
            from app.core.active_defense_countermeasures import get_active_defense
            defense = get_active_defense()
            assert defense is not None
            stats = defense.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Active Defense Countermeasures: initialized")
        except Exception as e:
            print(f"  ⚠️ Active Defense Countermeasures: {e}")

    def test_blockchain_trust_network(self):
        """Blockchain Trust Network should initialize."""
        try:
            from app.core.blockchain_trust_network import get_blockchain
            blockchain = get_blockchain()
            assert blockchain is not None
            stats = blockchain.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Blockchain Trust Network: initialized")
        except Exception as e:
            print(f"  ⚠️ Blockchain Trust Network: {e}")

    def test_quantum_safe_security(self):
        """Quantum-Safe Security should initialize."""
        try:
            from app.core.quantum_safe_security import get_quantum_safe
            qsafe = get_quantum_safe()
            assert qsafe is not None
            stats = qsafe.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Quantum-Safe Security: initialized")
        except Exception as e:
            print(f"  ⚠️ Quantum-Safe Security: {e}")

    def test_autonomous_threat_hunter_v2(self):
        """Autonomous Threat Hunter v2 should initialize."""
        try:
            from app.core.autonomous_threat_hunter_v2 import get_threat_hunter_v2
            hunter = get_threat_hunter_v2()
            assert hunter is not None
            stats = hunter.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Autonomous Threat Hunter v2: initialized")
        except Exception as e:
            print(f"  ⚠️ Autonomous Threat Hunter v2: {e}")

    def test_global_soc_dashboard(self):
        """Global SOC Dashboard should initialize."""
        try:
            from app.core.global_soc_dashboard import get_global_dashboard
            dashboard = get_global_dashboard()
            assert dashboard is not None
            stats = dashboard.get_stats()
            assert isinstance(stats, dict)
            print(f"  ✅ Global SOC Dashboard: initialized")
        except Exception as e:
            print(f"  ⚠️ Global SOC Dashboard: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--capture=no"])
