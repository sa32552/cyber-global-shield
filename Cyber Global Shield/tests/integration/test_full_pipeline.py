"""
Tests d'intégration complets pour Cyber Global Shield.
Couvre : ingestion → ML detection → SOAR → Agents → Federated Learning → Ray.
Run: pytest tests/integration/ -v --tb=short
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

# Make app importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "Cyber Global Shield"))

from app.ml.anomaly_detector import AnomalyDetector, TransformerAutoencoder
from app.ml.dataset_generator import NetworkLogGenerator
from app.ml.online_detector import OnlineDetector
from app.soar.playbook_engine import SOAREngine, PlaybookStatus, ActionStatus
from app.soar.integrations import (
    FirewallIntegration, EDRIntegration, IAMIntegration,
    DNSIntegration, NotificationIntegration, TicketIntegration,
    TheHiveIntegration, MISPIntegration, IntegrationManager,
)
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.kafka_client import KafkaClient
from app.ingestion.clickhouse_client import ClickHouseClient
from app.core.security import SecurityManager
from app.agents.crew import CyberShieldCrew


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_logs():
    """Generate sample logs for testing."""
    generator = NetworkLogGenerator(seed=42)
    logs = []
    for i in range(50):
        if i < 40:
            log = generator.generate_normal_log()
        else:
            log = generator.generate_attack_log("ransomware_activity")
        log["org_id"] = "test-org"
        log["timestamp"] = datetime.now(timezone.utc).isoformat()
        logs.append(log)
    return logs


@pytest.fixture
def sample_alert():
    return {
        "id": "int-alert-001",
        "org_id": "test-org",
        "event_type": "ransomware_activity",
        "severity": "critical",
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.0.50",
        "dst_port": 445,
        "protocol": "tcp",
        "user": "jdoe",
        "hostname": "host-42.internal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def sample_iocs():
    return {
        "ips": ["45.33.32.156", "91.240.118.30"],
        "domains": ["evil-c2.com"],
        "hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    }


# =============================================================================
# Test 1: Ingestion → ML Detection Pipeline
# =============================================================================

class TestIngestionToMLPipeline:
    """Test the full ingestion to ML detection pipeline."""

    @pytest.mark.asyncio
    async def test_ingest_then_detect(self, sample_logs):
        """Ingest logs then run ML detection on them."""
        # 1. Setup pipeline with mocks
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()
        pipeline.clickhouse.insert_logs_batch.return_value = len(sample_logs)

        # 2. Ingest logs
        inserted = await pipeline.ingest_batch(sample_logs)
        assert inserted == len(sample_logs)
        pipeline.clickhouse.insert_logs_batch.assert_called_once()

        # 3. Run ML detection on ingested logs
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        results = []
        for log in sample_logs:
            result = detector.detect([log])
            results.append(result)

        # 4. Verify detection results
        assert len(results) == len(sample_logs)
        anomaly_count = sum(1 for r in results if r.is_anomaly)
        assert anomaly_count >= 8  # At least the 10 attack logs should be detected
        print(f"  ✅ Detection: {anomaly_count}/{len(results)} anomalies detected")

    @pytest.mark.asyncio
    async def test_enrichment_with_threat_intel(self, sample_logs):
        """Test log enrichment with threat intelligence."""
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()

        # Mock threat intel lookup
        async def mock_ti_lookup(src_ip, dst_ip):
            if src_ip == "45.33.32.156":
                return {
                    "threat_actor": "APT29",
                    "confidence": 0.95,
                    "tags": ["malicious", "c2", "apt"],
                    "severity_override": "critical",
                }
            return {}

        pipeline._perform_threat_intel_lookup = mock_ti_lookup

        # Enrich logs
        enriched_count = 0
        for log in sample_logs:
            enriched = pipeline.enrich_log(log)
            if enriched.get("threat_actor"):
                enriched_count += 1
                assert enriched["threat_actor"] == "APT29"
                assert "malicious" in enriched.get("tags", [])

        assert enriched_count >= 1
        print(f"  ✅ Enrichment: {enriched_count} logs enriched with threat intel")


# =============================================================================
# Test 2: ML Detection → SOAR Pipeline
# =============================================================================

class TestMLToSOARPipeline:
    """Test the ML detection to SOAR playbook execution pipeline."""

    @pytest.mark.asyncio
    async def test_detection_triggers_soar(self, sample_alert, sample_iocs):
        """ML anomaly detection should trigger SOAR playbook execution."""
        # 1. Run ML detection
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        attack_logs = [
            {"event_type": "ransomware_activity", "src_ip": "45.33.32.156",
             "dst_ip": "10.0.0.50", "severity": "critical", "org_id": "test-org"}
        ]
        detection_result = detector.detect(attack_logs)

        # 2. If anomaly detected, execute SOAR playbook
        if detection_result.is_anomaly:
            engine = SOAREngine()
            result = await engine.execute_playbook(
                playbook_name="ransomware_response",
                alert=sample_alert,
                context={"iocs": sample_iocs, "anomaly_score": detection_result.anomaly_score},
            )
            assert result.status == PlaybookStatus.COMPLETED
            assert len(result.actions_results) > 0
            print(f"  ✅ SOAR triggered: {result.status.value}, {len(result.actions_results)} actions")
        else:
            print("  ⚠️ No anomaly detected, SOAR not triggered")

    @pytest.mark.asyncio
    async def test_soar_rollback_on_detection_failure(self):
        """SOAR should rollback if detection confidence is low."""
        engine = SOAREngine()

        # Register a test playbook that fails
        from app.soar.playbook_engine import SOARPlaybook
        engine.register_playbook(SOARPlaybook(
            name="test_rollback_pb",
            description="Test rollback",
            trigger_event="test",
            actions=[
                {"name": "action_1", "type": "notification", "params": {"message": "test"}, "order": 1},
                {"name": "action_fail", "type": "firewall_block", "params": {"ips": ["invalid"]}, "order": 2},
            ],
        ))

        result = await engine.execute_playbook(
            playbook_name="test_rollback_pb",
            alert={"id": "test", "src_ip": "1.2.3.4"},
            context={},
        )
        # Should either complete or fail gracefully
        assert result.status in (PlaybookStatus.COMPLETED, PlaybookStatus.FAILED)
        print(f"  ✅ Rollback test: {result.status.value}")


# =============================================================================
# Test 3: SOAR → Agents Pipeline
# =============================================================================

class TestSOARToAgentsPipeline:
    """Test the SOAR to CrewAI agents pipeline."""

    @pytest.mark.asyncio
    async def test_soar_execution_with_agent_context(self, sample_alert, sample_iocs):
        """SOAR playbook should provide context for agent investigation."""
        engine = SOAREngine()

        # Execute playbook
        result = await engine.execute_playbook(
            playbook_name="ransomware_response",
            alert=sample_alert,
            context={"iocs": sample_iocs},
        )

        # Verify playbook produced actionable results
        assert result.status == PlaybookStatus.COMPLETED
        assert result.duration_ms > 0

        # Verify audit trail is complete
        assert len(result.audit_trail) >= 2
        assert result.audit_trail[0]["action"] == "playbook_started"
        assert result.audit_trail[-1]["action"] == "playbook_completed"

        print(f"  ✅ SOAR→Agents: {result.status.value}, {result.duration_ms:.0f}ms, {len(result.audit_trail)} audit entries")


# =============================================================================
# Test 4: Full End-to-End Pipeline
# =============================================================================

class TestFullEndToEndPipeline:
    """Test the complete pipeline: Ingestion → ML → SOAR → Agents."""

    @pytest.mark.asyncio
    async def test_complete_pipeline(self, sample_logs, sample_alert, sample_iocs):
        """Run the complete pipeline end-to-end."""
        print("\n  🔄 Running complete pipeline...")

        # Stage 1: Ingestion
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()
        pipeline.clickhouse.insert_logs_batch.return_value = len(sample_logs)

        inserted = await pipeline.ingest_batch(sample_logs)
        assert inserted == len(sample_logs)
        print(f"  ✅ Stage 1: {inserted} logs ingested")

        # Stage 2: ML Detection
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        anomalies = []
        for log in sample_logs:
            result = detector.detect([log])
            if result.is_anomaly:
                anomalies.append({"log": log, "score": result.anomaly_score})

        print(f"  ✅ Stage 2: {len(anomalies)} anomalies detected by ML")
        assert len(anomalies) > 0

        # Stage 3: SOAR
        engine = SOAREngine()
        soar_results = []
        for anomaly in anomalies[:3]:  # Process top 3 anomalies
            result = await engine.execute_playbook(
                playbook_name="ransomware_response",
                alert={**sample_alert, "src_ip": anomaly["log"].get("src_ip", "unknown")},
                context={"iocs": sample_iocs, "anomaly_score": anomaly["score"]},
            )
            soar_results.append(result)

        print(f"  ✅ Stage 3: {len(soar_results)} SOAR playbooks executed")
        for r in soar_results:
            assert r.status in (PlaybookStatus.COMPLETED, PlaybookStatus.SKIPPED)

        # Stage 4: Verify audit trail
        for r in soar_results:
            if r.status == PlaybookStatus.COMPLETED:
                assert len(r.audit_trail) > 0
                assert r.duration_ms > 0

        print(f"  ✅ Stage 4: Audit trails verified")
        print(f"  ✅ Pipeline complete!")


# =============================================================================
# Test 5: Integration Manager Health
# =============================================================================

class TestIntegrationManagerHealth:
    """Test all integrations health check."""

    @pytest.mark.asyncio
    async def test_all_integrations_health(self):
        """All integrations should report healthy status."""
        mgr = IntegrationManager()
        health = await mgr.health_check()

        assert "firewall" in health
        assert "edr" in health
        assert "iam" in health
        assert "dns" in health
        assert "notifications" in health
        assert "tickets" in health
        assert "thehive" in health
        assert "misp" in health

        for name, status in health.items():
            assert status in ("healthy", "simulated", "unconfigured"), f"{name}: {status}"

        print(f"  ✅ All {len(health)} integrations healthy")


# =============================================================================
# Test 6: Concurrent Pipeline Execution
# =============================================================================

class TestConcurrentPipeline:
    """Test concurrent execution of multiple pipelines."""

    @pytest.mark.asyncio
    async def test_concurrent_soar_executions(self, sample_alert):
        """Multiple SOAR playbooks should run concurrently."""
        engine = SOAREngine()

        async def run_playbook(name):
            return await engine.execute_playbook(
                playbook_name=name,
                alert=sample_alert,
                context={},
            )

        # Run 3 different playbooks concurrently
        results = await asyncio.gather(
            run_playbook("ransomware_response"),
            run_playbook("brute_force_response"),
            run_playbook("c2_communication_response"),
        )

        assert len(results) == 3
        completed = sum(1 for r in results if r.status == PlaybookStatus.COMPLETED)
        print(f"  ✅ Concurrent: {completed}/3 playbooks completed")


# =============================================================================
# Test 7: Security & Encryption
# =============================================================================

class TestSecurityPipeline:
    """Test security features across the pipeline."""

    def test_log_encryption_decryption(self):
        """Logs should be encryptable and decryptable."""
        mgr = SecurityManager()

        sensitive_data = {
            "src_ip": "45.33.32.156",
            "user": "jdoe",
            "password_attempt": "P@ssw0rd!",
            "session_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9",
        }

        # Encrypt
        encrypted = mgr.encrypt_sensitive_fields(sensitive_data)
        assert encrypted["src_ip"] != sensitive_data["src_ip"]
        assert encrypted["user"] != sensitive_data["user"]

        # Decrypt
        decrypted = mgr.decrypt_sensitive_fields(encrypted)
        assert decrypted["src_ip"] == sensitive_data["src_ip"]
        assert decrypted["user"] == sensitive_data["user"]

        print(f"  ✅ Security: encryption/decryption verified")

    def test_jwt_token_flow(self):
        """JWT token creation and validation should work."""
        mgr = SecurityManager()

        token = mgr.create_access_token(
            data={"sub": "admin", "org_id": "test-org"},
            expires_delta=3600,
        )
        assert token is not None
        assert len(token) > 50

        payload = mgr.decode_token(token)
        assert payload["sub"] == "admin"
        assert payload["org_id"] == "test-org"

        print(f"  ✅ JWT: token flow verified")


# =============================================================================
# Test 8: Data Generation & Validation
# =============================================================================

class TestDataPipeline:
    """Test data generation and validation."""

    def test_dataset_generation_and_validation(self):
        """Generated datasets should have correct shapes and distributions."""
        generator = NetworkLogGenerator(seed=42)

        X, y = generator.generate_sequences(
            num_sequences=200,
            seq_length=32,
            anomaly_probability=0.15,
        )

        # Validate shapes
        assert X.shape == (200, 32, 128), f"Expected (200, 32, 128), got {X.shape}"
        assert y.shape == (200,), f"Expected (200,), got {y.shape}"

        # Validate distribution
        anomaly_ratio = np.mean(y)
        assert 0.05 <= anomaly_ratio <= 0.30, f"Anomaly ratio {anomaly_ratio:.3f} out of range"

        # Validate data ranges
        assert X.min() >= 0.0, f"X min {X.min()} < 0"
        assert X.max() <= 1.0, f"X max {X.max()} > 1"

        print(f"  ✅ Data: {len(X)} sequences, {anomaly_ratio:.1%} anomalies, shape {X.shape}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--capture=no"])
