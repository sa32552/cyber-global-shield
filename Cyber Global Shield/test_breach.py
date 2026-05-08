"""
Cyber Global Shield — Comprehensive Test Suite
Tests: Ingestion Pipeline, ML Detection, Agents, SOAR, API, Simulation
Run: pytest test_breach.py -v
"""

import os
import sys
import json
import pytest
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock

# Make app importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

# =============================================================================
# Dataset Generator Tests
# =============================================================================

class TestDatasetGenerator:
    def test_generate_normal_log(self):
        from app.ml.dataset_generator import NetworkLogGenerator
        gen = NetworkLogGenerator(seed=42)
        log = gen.generate_normal_log(profile="workstation")

        assert log["org_id"] == "org-synthetic"
        assert log["severity"] == "info"
        assert log["source"] in ("zeek", "suricata", "osquery")
        assert log["src_ip"].startswith("10.")
        assert log["dst_port"] in (80, 443, 53, 22, 3389)
        assert log["protocol"] in ("tcp", "udp", "icmp")
        assert log["is_attack"] is False

    def test_generate_attack_log(self):
        from app.ml.dataset_generator import NetworkLogGenerator
        gen = NetworkLogGenerator(seed=42)
        log = gen.generate_attack_log("ransomware_activity")

        assert log["event_type"] == "ransomware_activity"
        assert log["severity"] in ("high", "critical")
        assert log["dst_port"] == 445
        assert "attack_type" in log["raw_payload"]
        assert log["raw_payload"]["mitre_tactic"] == "TA0040"

    def test_generate_all_attack_types(self):
        from app.ml.dataset_generator import NetworkLogGenerator
        gen = NetworkLogGenerator(seed=42)

        for attack_type in gen.ATTACK_PATTERNS:
            log = gen.generate_attack_log(attack_type)
            assert log is not None
            assert log["event_type"] is not None

    def test_generate_dataset(self):
        from app.ml.dataset_generator import NetworkLogGenerator
        gen = NetworkLogGenerator(seed=42)
        all_logs, normal_logs = gen.generate_dataset(
            total_logs=1000,
            attack_ratio=0.1,
            time_window_hours=1,
        )

        assert len(all_logs) == 1000
        assert len(normal_logs) == 900
        assert sum(1 for l in all_logs if l.get("is_attack")) == 100

    def test_generate_sequences(self):
        from app.ml.dataset_generator import NetworkLogGenerator
        gen = NetworkLogGenerator(seed=42)
        X, y = gen.generate_sequences(
            num_sequences=200,
            seq_length=16,
            anomaly_probability=0.1,
        )

        assert X.shape == (200, 16, 128)
        assert y.shape == (200,)
        assert y.sum() > 0  # Some anomalies present
        assert y.sum() < 200  # Not all anomalies


# =============================================================================
# ML Anomaly Detector Tests
# =============================================================================

class TestAnomalyDetector:
    def test_model_creation(self):
        from app.ml.anomaly_detector import TransformerAutoencoder
        model = TransformerAutoencoder(
            input_dim=128,
            d_model=128,
            nhead=4,
            num_encoder_layers=2,
            num_decoder_layers=1,
            dim_feedforward=256,
            latent_dim=32,
        )
        n_params = sum(p.numel() for p in model.parameters())
        assert n_params > 100000  # Model has substantial params

    def test_model_forward(self):
        import torch
        from app.ml.anomaly_detector import TransformerAutoencoder

        model = TransformerAutoencoder(
            input_dim=128, d_model=128, nhead=4,
            num_encoder_layers=2, num_decoder_layers=1,
        )

        batch = torch.randn(4, 16, 128)  # 4 sequences, 16 long, 128 dims
        reconstructed, latent = model(batch)

        assert reconstructed.shape == batch.shape
        assert latent.shape == (4, 32)

    def test_detector_preprocessing(self):
        from app.ml.anomaly_detector import create_default_detector

        detector = create_default_detector()
        logs = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "tcp", "event_type": "scan"},
        ]
        tensor = detector.preprocess(logs, seq_len=16)
        assert tensor.shape == (1, 16, 128)

    def test_detection_without_model(self):
        from app.ml.anomaly_detector import create_default_detector

        detector = create_default_detector()
        logs = [
            {"src_ip": "10.0.0.1", "dst_ip": "45.33.32.156", "protocol": "tcp", "event_type": "scan"}
        ]
        result = detector.detect(logs)

        assert hasattr(result, 'anomaly_score')
        assert hasattr(result, 'is_anomaly')
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_detection_result_structure(self):
        from app.ml.anomaly_detector import AnomalyDetectionResult

        result = AnomalyDetectionResult(
            anomaly_score=0.95,
            reconstruction_error=0.5,
            is_anomaly=True,
            threshold_used=0.9,
            explanation="Test anomaly",
        )

        assert result.anomaly_score == 0.95
        assert result.is_anomaly is True


# =============================================================================
# Pipeline & Ingestion Tests
# =============================================================================

class TestPipeline:
    def test_normalize_log(self):
        from app.ingestion.pipeline import IngestionPipeline
        pipeline = IngestionPipeline()

        raw = {
            "org_id": "test-org",
            "source": "zeek",
            "event_type": "connection",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "tcp",
        }
        normalized = pipeline.normalize_log(raw)

        assert normalized["org_id"] == "test-org"
        assert normalized["source"] == "zeek"
        assert normalized["src_ip"] == "10.0.0.1"

    def test_enrich_log(self):
        from app.ingestion.pipeline import IngestionPipeline
        pipeline = IngestionPipeline()

        log = {"event_type": "brute_force", "severity": "info"}
        enriched = pipeline.enrich_log(log)

        assert enriched["severity"] == "high"
        assert enriched["mitre_tactic"] == "TA0006"

    def test_timestamp_parsing(self):
        from app.ingestion.pipeline import IngestionPipeline
        pipeline = IngestionPipeline()

        # Unix timestamp
        ts = pipeline._parse_timestamp(1714600000)
        assert isinstance(ts, datetime)

        # ISO string
        ts = pipeline._parse_timestamp("2024-05-01T12:00:00Z")
        assert isinstance(ts, datetime)

        # None
        ts = pipeline._parse_timestamp(None)
        assert isinstance(ts, datetime)

    def test_mitre_mapping(self):
        from app.ingestion.pipeline import IngestionPipeline
        pipeline = IngestionPipeline()

        test_cases = {
            "ransomware_activity": ("TA0040", "T1486"),
            "c2_communication": ("TA0011", "T1071"),
            "data_exfiltration": ("TA0010", "T1041"),
            "lateral_movement": ("TA0008", "T1021"),
        }

        for event_type, (tactic, technique) in test_cases.items():
            log = pipeline.enrich_log({"event_type": event_type, "severity": "info"})
            assert log["mitre_tactic"] == tactic
            assert log["mitre_technique"] == technique


# =============================================================================
# SOAR Playbook Tests
# =============================================================================

class TestSOAR:
    def test_playbook_registration(self):
        from app.soar.playbook_engine import SOAREngine
        engine = SOAREngine()

        assert len(engine.playbooks) == 5
        assert "ransomware_response" in engine.playbooks
        assert "lateral_movement_response" in engine.playbooks
        assert "data_exfiltration_response" in engine.playbooks
        assert "c2_communication_response" in engine.playbooks
        assert "brute_force_response" in engine.playbooks

    def test_ransomware_playbook_actions(self):
        from app.soar.playbook_engine import SOAREngine
        engine = SOAREngine()

        pb = engine.playbooks["ransomware_response"]
        assert pb.requires_approval is False
        assert pb.cooldown_seconds == 60
        assert len(pb.actions) == 8
        # First action should be identify_patient_zero
        assert pb.actions[0]["name"] == "identify_patient_zero"

    def test_data_exfiltration_requires_approval(self):
        from app.soar.playbook_engine import SOAREngine
        engine = SOAREngine()

        pb = engine.playbooks["data_exfiltration_response"]
        assert pb.requires_approval is True

    def test_template_resolution(self):
        from app.soar.playbook_engine import SOAREngine
        engine = SOAREngine()

        action = {"params": {"ips": "{{ iocs.ips }}", "host": "{{ alert.src_ip }}"}}
        context = {
            "iocs": {"ips": ["45.33.32.156"]},
            "alert": {"src_ip": "10.0.0.50"},
        }
        resolved = engine._resolve_template(action, context)
        assert resolved["params"]["ips"] == ["45.33.32.156"]
        assert resolved["params"]["host"] == "10.0.0.50"

    def test_action_handlers_registered(self):
        from app.soar.playbook_engine import SOAREngine
        engine = SOAREngine()

        expected_handlers = [
            "firewall_block", "dns_sinkhole", "edr_action", "iam_action",
            "network_segment", "forensic_snapshot", "notification", "ticket",
        ]
        for handler in expected_handlers:
            assert handler in engine._action_handlers, f"Handler {handler} missing"


# =============================================================================
# Config Tests
# =============================================================================

class TestConfig:
    def test_settings_load(self):
        from app.core.config import settings

        assert settings.APP_NAME == "Cyber Global Shield"
        assert settings.APP_VERSION == "2.0.0"
        assert settings.PORT == 8000
        assert settings.WORKERS == 4

    def test_kafka_config(self):
        from app.core.config import settings
        assert settings.KAFKA_BOOTSTRAP_SERVERS
        assert settings.KAFKA_TOPIC_LOGS
        assert settings.KAFKA_TOPIC_ALERTS

    def test_soar_integration_configs(self):
        from app.core.config import settings
        assert hasattr(settings, 'FIREWALL_URL')
        assert hasattr(settings, 'EDR_URL')
        assert hasattr(settings, 'IAM_URL')
        assert hasattr(settings, 'DNS_URL')
        assert hasattr(settings, 'SLACK_WEBHOOK_URL')
        assert hasattr(settings, 'JIRA_URL')


# =============================================================================
# Security Tests
# =============================================================================

class TestSecurity:
    def test_password_hashing(self):
        from app.core.security import hash_password, verify_password

        hashed = hash_password("test_password")
        assert hashed != "test_password"
        assert verify_password("test_password", hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_jwt_token_creation(self):
        from app.core.security import create_access_token, verify_token

        token = create_access_token(
            subject="test_user",
            org_id="test_org",
            role="analyst",
        )
        assert isinstance(token, str)
        assert len(token) > 50

    def test_jwt_token_verification(self):
        from app.core.security import create_access_token, verify_token

        token = create_access_token(
            subject="test_user",
            org_id="test_org",
            role="analyst",
        )
        payload = verify_token(token)
        assert payload.sub == "test_user"
        assert payload.org_id == "test_org"
        assert payload.role == "analyst"

    def test_jwt_invalid_token(self):
        from app.core.security import verify_token
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            verify_token("invalid_token_12345")


# =============================================================================
# Log Watcher Tests
# =============================================================================

class TestLogWatcher:
    def test_zeek_conn_parsing(self):
        from app.ingestion.log_watcher import LogWatcher
        watcher = LogWatcher(zeek_log_dir="/tmp", suricata_eve_path="/tmp/eve.json")

        line = "1714600000.000000\tC12345\t10.0.0.1\t50000\t10.0.0.2\t80\ttcp\thttp\t1.5\t1000\t5000\tSF\t-\t-\t0\tShAdDf\t10\t500\t15\t800\t-"
        result = watcher._parse_zeek_line(line, "conn")

        assert result is not None
        assert result["source"] == "zeek"
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["dst_port"] == 80
        assert result["protocol"] == "tcp"

    def test_zeek_ssh_brute_force_detection(self):
        from app.ingestion.log_watcher import LogWatcher
        watcher = LogWatcher(zeek_log_dir="/tmp", suricata_eve_path="/tmp/eve.json")

        # Auth failure = F means brute force
        line = "1714600000\tC12345\t45.33.32.156\t60000\t10.0.0.1\t22\tSSH-2.0\tF\t50\tINBOUND\troot\tOpenSSH_7.4\t-\t-\t-\t-\t-\t-"
        result = watcher._parse_zeek_line(line, "ssh")

        assert result is not None
        assert result["event_type"] == "brute_force"
        assert result["severity"] == "high"

    def test_suricata_alert_parsing(self):
        from app.ingestion.log_watcher import LogWatcher
        watcher = LogWatcher(zeek_log_dir="/tmp", suricata_eve_path="/tmp/eve.json")

        eve = json.dumps({
            "timestamp": "2024-05-01T12:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "45.33.32.156",
            "dest_ip": "10.0.0.50",
            "src_port": 54321,
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "signature": "ET EXPLOIT SMB EternalBlue",
                "category": "Exploit",
                "severity": 1,
            },
        })
        result = watcher._parse_suricata_line(eve)

        assert result is not None
        assert result["source"] == "suricata"
        assert result["severity"] == "critical"
        assert result["alert_signature"] == "ET EXPLOIT SMB EternalBlue"

    def test_suricata_dns_parsing(self):
        from app.ingestion.log_watcher import LogWatcher
        watcher = LogWatcher(zeek_log_dir="/tmp", suricata_eve_path="/tmp/eve.json")

        eve = json.dumps({
            "timestamp": "2024-05-01T12:00:00.000000+0000",
            "event_type": "dns",
            "src_ip": "10.0.0.1",
            "dest_ip": "8.8.8.8",
            "dns": {"query": "evil-c2.com", "type": "A"},
        })
        result = watcher._parse_suricata_line(eve)

        assert result is not None
        assert result["source"] == "suricata"
        assert result["event_type"] == "dns"


# =============================================================================
# Performance Benchmarks
# =============================================================================

class TestPerformance:
    def test_dataset_generation_speed(self):
        """Dataset generation should be reasonably fast."""
        import time
        from app.ml.dataset_generator import NetworkLogGenerator

        gen = NetworkLogGenerator(seed=42)
        start = time.time()
        logs, _ = gen.generate_dataset(total_logs=5000, attack_ratio=0.05)
        duration = time.time() - start

        assert len(logs) == 5000
        assert duration < 10  # Should complete in < 10 seconds

    def test_log_preprocessing_speed(self):
        """Preprocessing 1000 logs should be fast."""
        import time
        from app.ml.anomaly_detector import create_default_detector

        detector = create_default_detector()
        logs = [
            {"src_ip": f"10.0.0.{i%255}", "dst_ip": f"10.0.1.{i%255}",
             "protocol": "tcp", "event_type": "connection"}
            for i in range(1000)
        ]

        start = time.time()
        tensor = detector.preprocess(logs, seq_len=64)
        duration = time.time() - start

        assert tensor.shape == (1, 64, 128)
        assert duration < 1.0  # Should be sub-second

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])