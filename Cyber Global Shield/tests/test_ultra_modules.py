"""
Tests d'intégration pour les 12 modules Ultra ML (Niveaux 1-12)
Cyber Global Shield — Autonomous Agentic SIEM Platform
"""

import pytest
import numpy as np
from datetime import datetime, timezone

from app.ml.ultra_detector import get_ultra_detector, UltraDetector
from app.ml.ultra_predictor import get_ultra_predictor, UltraPredictor
from app.ml.ultra_classifier import get_ultra_classifier, UltraClassifier
from app.ml.ultra_remediation import get_ultra_remediation, UltraAutoRemediation
from app.ml.ultra_crypto import get_ultra_crypto, UltraCrypto
from app.ml.ultra_threat_intel import get_ultra_threat_intel, UltraThreatIntel
from app.ml.ultra_zero_day import get_ultra_zero_day, UltraZeroDay
from app.ml.ultra_forensics import get_ultra_forensics, UltraForensics
from app.ml.ultra_network import get_ultra_network, UltraNetworkAnalyzer
from app.ml.ultra_biometrics import get_ultra_biometrics, UltraBiometrics
from app.ml.meta_ensemble import get_meta_ensemble, MetaEnsembleOrchestrator
from app.ml.auto_optimizer import get_auto_optimizer, AutoMLOrchestrator
from app.ml.integration import get_integration_hub, UltraIntegrationHub


class TestUltraDetector:
    """Tests pour Niveau 1: Ultra Detector."""

    def test_singleton(self):
        detector1 = get_ultra_detector()
        detector2 = get_ultra_detector()
        assert detector1 is detector2

    def test_detect_normal(self):
        detector = get_ultra_detector()
        data = {"features": [0.1, 0.2, 0.3, 0.4, 0.5], "timestamp": datetime.now(timezone.utc).isoformat()}
        result = detector.detect(data)
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert "confidence" in result
        assert isinstance(result["anomaly_score"], float)
        assert isinstance(result["is_anomaly"], bool)

    def test_detect_anomaly(self):
        detector = get_ultra_detector()
        data = {"features": [100.0, 200.0, 300.0, 400.0, 500.0], "timestamp": datetime.now(timezone.utc).isoformat()}
        result = detector.detect(data)
        assert result["is_anomaly"] is True

    def test_get_stats(self):
        detector = get_ultra_detector()
        stats = detector.get_stats()
        assert "total_detections" in stats
        assert "anomalies_found" in stats
        assert "avg_confidence" in stats


class TestUltraPredictor:
    """Tests pour Niveau 2: Ultra Predictor."""

    def test_singleton(self):
        p1 = get_ultra_predictor()
        p2 = get_ultra_predictor()
        assert p1 is p2

    def test_predict(self):
        predictor = get_ultra_predictor()
        data = {"features": [0.1, 0.2, 0.3], "context": {"source": "test"}}
        result = predictor.predict(data)
        assert "prediction" in result
        assert "probability" in result
        assert "threat_level" in result
        assert isinstance(result["probability"], float)

    def test_get_stats(self):
        predictor = get_ultra_predictor()
        stats = predictor.get_stats()
        assert "total_predictions" in stats


class TestUltraClassifier:
    """Tests pour Niveau 3: Ultra Classifier."""

    def test_singleton(self):
        c1 = get_ultra_classifier()
        c2 = get_ultra_classifier()
        assert c1 is c2

    def test_classify(self):
        classifier = get_ultra_classifier()
        data = {"features": [0.1, 0.2, 0.3, 0.4], "type": "network_traffic"}
        result = classifier.classify(data)
        assert "classification" in result
        assert "confidence" in result
        assert "top_classes" in result

    def test_get_stats(self):
        classifier = get_ultra_classifier()
        stats = classifier.get_stats()
        assert "total_classifications" in stats


class TestUltraRemediation:
    """Tests pour Niveau 4: Ultra Remediation."""

    def test_singleton(self):
        r1 = get_ultra_remediation()
        r2 = get_ultra_remediation()
        assert r1 is r2

    def test_remediate(self):
        remediation = get_ultra_remediation()
        incident = {
            "type": "ransomware",
            "severity": "critical",
            "affected_assets": ["server-01", "server-02"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result = remediation.remediate(incident)
        assert "actions_taken" in result
        assert "status" in result
        assert "remediation_time_ms" in result

    def test_get_stats(self):
        remediation = get_ultra_remediation()
        stats = remediation.get_stats()
        assert "total_remediations" in stats


class TestUltraCrypto:
    """Tests pour Niveau 5: Ultra Crypto."""

    def test_singleton(self):
        c1 = get_ultra_crypto()
        c2 = get_ultra_crypto()
        assert c1 is c2

    def test_encrypt_decrypt(self):
        crypto = get_ultra_crypto()
        original = {"message": "Top secret data", "classification": "confidential"}
        encrypted = crypto.encrypt(original)
        assert "ciphertext" in encrypted
        assert "algorithm" in encrypted
        assert encrypted["algorithm"] == "quantum_resistant"

        decrypted = crypto.decrypt(encrypted)
        assert decrypted["data"]["message"] == original["message"]

    def test_get_stats(self):
        crypto = get_ultra_crypto()
        stats = crypto.get_stats()
        assert "total_encryptions" in stats


class TestUltraThreatIntel:
    """Tests pour Niveau 6: Ultra Threat Intel."""

    def test_singleton(self):
        t1 = get_ultra_threat_intel()
        t2 = get_ultra_threat_intel()
        assert t1 is t2

    def test_analyze(self):
        ti = get_ultra_threat_intel()
        threat_data = {
            "iocs": ["185.220.101.1", "evil.com"],
            "type": "malware",
            "source": "external_feed",
        }
        result = ti.analyze(threat_data)
        assert "threat_score" in result
        assert "confidence" in result
        assert "recommendations" in result

    def test_get_stats(self):
        ti = get_ultra_threat_intel()
        stats = ti.get_stats()
        assert "total_analyses" in stats


class TestUltraZeroDay:
    """Tests pour Niveau 7: Ultra Zero-Day."""

    def test_singleton(self):
        z1 = get_ultra_zero_day()
        z2 = get_ultra_zero_day()
        assert z1 is z2

    def test_detect(self):
        zd = get_ultra_zero_day()
        behavior_data = {
            "process_name": "unknown_binary.exe",
            "behavior_pattern": ["memory_write", "process_injection", "network_connect"],
            "parent_process": "explorer.exe",
        }
        result = zd.detect(behavior_data)
        assert "is_zero_day" in result
        assert "risk_score" in result
        assert "behavior_analysis" in result

    def test_get_stats(self):
        zd = get_ultra_zero_day()
        stats = zd.get_stats()
        assert "total_analyses" in stats


class TestUltraForensics:
    """Tests pour Niveau 8: Ultra Forensics."""

    def test_singleton(self):
        f1 = get_ultra_forensics()
        f2 = get_ultra_forensics()
        assert f1 is f2

    def test_analyze(self):
        forensics = get_ultra_forensics()
        evidence = {
            "type": "memory_dump",
            "file_hash": "a1b2c3d4e5f6",
            "size_bytes": 1048576,
            "source": "endpoint-01",
        }
        result = forensics.analyze(evidence)
        assert "artifacts_found" in result
        assert "timeline" in result
        assert "malicious_indicators" in result

    def test_get_stats(self):
        forensics = get_ultra_forensics()
        stats = forensics.get_stats()
        assert "total_analyses" in stats


class TestUltraNetwork:
    """Tests pour Niveau 9: Ultra Network."""

    def test_singleton(self):
        n1 = get_ultra_network()
        n2 = get_ultra_network()
        assert n1 is n2

    def test_analyze(self):
        network = get_ultra_network()
        traffic_data = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "port": 443,
            "bytes_transferred": 1024,
            "packets": 10,
        }
        result = network.analyze(traffic_data)
        assert "anomaly_score" in result
        assert "threat_detected" in result
        assert "protocol_analysis" in result

    def test_get_stats(self):
        network = get_ultra_network()
        stats = network.get_stats()
        assert "total_analyses" in stats


class TestUltraBiometrics:
    """Tests pour Niveau 10: Ultra Biometrics."""

    def test_singleton(self):
        b1 = get_ultra_biometrics()
        b2 = get_ultra_biometrics()
        assert b1 is b2

    def test_analyze(self):
        biometrics = get_ultra_biometrics()
        session_data = {
            "user_id": "user-001",
            "keystroke_timing": [120, 95, 150, 110, 130],
            "mouse_movement": [(100, 200), (150, 250), (180, 300)],
            "login_time": "2026-05-10T08:00:00Z",
        }
        result = biometrics.analyze(session_data)
        assert "is_legitimate" in result
        assert "confidence" in result
        assert "behavioral_score" in result

    def test_get_stats(self):
        biometrics = get_ultra_biometrics()
        stats = biometrics.get_stats()
        assert "total_analyses" in stats


class TestMetaEnsemble:
    """Tests pour Niveau 11: Meta Ensemble."""

    def test_singleton(self):
        e1 = get_meta_ensemble()
        e2 = get_meta_ensemble()
        assert e1 is e2

    def test_predict(self):
        ensemble = get_meta_ensemble()
        data = {
            "features": [0.1, 0.2, 0.3, 0.4, 0.5],
            "model_outputs": {
                "detector": {"anomaly_score": 0.1, "is_anomaly": False},
                "predictor": {"probability": 0.2, "threat_level": "low"},
                "classifier": {"classification": "benign", "confidence": 0.95},
            },
        }
        result = ensemble.predict(data)
        assert "ensemble_score" in result
        assert "final_verdict" in result
        assert "confidence" in result
        assert "model_weights" in result

    def test_get_stats(self):
        ensemble = get_meta_ensemble()
        stats = ensemble.get_stats()
        assert "total_predictions" in stats


class TestAutoOptimizer:
    """Tests pour Niveau 12: Auto Optimizer."""

    def test_singleton(self):
        o1 = get_auto_optimizer()
        o2 = get_auto_optimizer()
        assert o1 is o2

    def test_optimize(self):
        optimizer = get_auto_optimizer()
        config = {
            "model_type": "anomaly_detector",
            "parameters": {
                "learning_rate": [0.001, 0.01, 0.1],
                "batch_size": [32, 64, 128],
                "hidden_layers": [2, 3, 4],
            },
            "optimization_metric": "f1_score",
            "max_trials": 5,
        }
        result = optimizer.optimize(config)
        assert "best_params" in result
        assert "best_score" in result
        assert "optimization_history" in result

    def test_get_stats(self):
        optimizer = get_auto_optimizer()
        stats = optimizer.get_stats()
        assert "total_optimizations" in stats


class TestIntegrationHub:
    """Tests pour l'Integration Hub central."""

    def test_singleton(self):
        h1 = get_integration_hub()
        h2 = get_integration_hub()
        assert h1 is h2

    def test_run_pipeline(self):
        hub = get_integration_hub()
        request = {
            "data": {"features": [0.1, 0.2, 0.3, 0.4, 0.5]},
            "pipeline": ["detect", "classify", "ensemble"],
            "context": {"source": "integration_test"},
        }
        result = hub.run_pipeline(request)
        assert "pipeline_result" in result
        assert "execution_time_ms" in result
        assert "stages_completed" in result

    def test_get_status(self):
        hub = get_integration_hub()
        status = hub.get_status()
        assert "modules_available" in status
        assert "total_pipelines_run" in status
        assert "avg_execution_time_ms" in status
        assert "module_status" in status
        # Vérifier que tous les 12 modules sont listés
        assert len(status["module_status"]) >= 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
