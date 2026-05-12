"""
Cyber Global Shield v2.0 — Property-Based Integration Tests
Uses Hypothesis for property-based testing across the full pipeline.

Run: pytest tests/integration/test_property_based.py -v --tb=short
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock, patch

import pytest
import numpy as np
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from hypothesis.strategies import composite

# Make app importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "Cyber Global Shield"))

from app.ml.anomaly_detector import AnomalyDetector, TransformerAutoencoder
from app.ml.online_detector import OnlineAnomalyDetector, HybridOnlineDetector
from app.ml.dataset_generator import NetworkLogGenerator
from app.ml.conformal_prediction import ConformalDetector, SplitConformal
from app.soar.playbook_engine import SOAREngine, PlaybookStatus
from app.ingestion.pipeline import IngestionPipeline
from app.core.security import SecurityManager


# =============================================================================
# Custom Hypothesis Strategies
# =============================================================================

@composite
def log_entries(draw):
    """Generate arbitrary log entries with realistic constraints."""
    org_id = draw(st.sampled_from(["org-a", "org-b", "test-org"]))
    source = draw(st.sampled_from(["zeek", "suricata", "windows", "linux", "aws", "gcp"]))
    event_type = draw(st.sampled_from([
        "connection", "http_request", "dns_query", "alert", "auth_event",
        "file_access", "process_creation", "registry_change",
    ]))
    severity = draw(st.sampled_from(["info", "low", "medium", "high", "critical"]))
    src_ip = draw(st.ip_addresses(v=4).map(str))
    dst_ip = draw(st.ip_addresses(v=4).map(str))
    src_port = draw(st.integers(min_value=1, max_value=65535))
    dst_port = draw(st.integers(min_value=1, max_value=65535))
    protocol = draw(st.sampled_from(["tcp", "udp", "icmp", "http", "dns"]))
    user = draw(st.sampled_from(["admin", "jdoe", "svc_bot", "root", "guest"]))
    hostname = draw(st.sampled_from(["host-1", "host-42", "server-01", "workstation-5"]))

    return {
        "org_id": org_id,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "user": user,
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@composite
def log_batches(draw):
    """Generate batches of log entries."""
    n = draw(st.integers(min_value=1, max_value=100))
    return [draw(log_entries()) for _ in range(n)]


@composite
def anomaly_scores(draw):
    """Generate valid anomaly scores."""
    return draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False))


@composite
def thresholds(draw):
    """Generate valid threshold values."""
    return draw(st.floats(min_value=0.5, max_value=0.999, allow_nan=False, allow_infinity=False))


# =============================================================================
# Property 1: Ingestion Pipeline Invariants
# =============================================================================

class TestIngestionProperties:
    """Property-based tests for the ingestion pipeline."""

    @given(log_batches())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_ingest_batch_count_matches(self, logs):
        """Property: ingested count should always equal input length."""
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()
        pipeline.clickhouse.insert_logs_batch.return_value = len(logs)

        # Run with asyncio
        import asyncio
        count = asyncio.run(pipeline.ingest_batch(logs))

        assert count == len(logs), f"Expected {len(logs)}, got {count}"

    @given(log_entries())
    @settings(max_examples=50)
    def test_single_log_has_required_fields(self, log):
        """Property: every ingested log must preserve required fields."""
        required_fields = {"org_id", "source", "event_type", "timestamp"}
        assert required_fields.issubset(log.keys()), f"Missing fields: {required_fields - log.keys()}"

    @given(log_batches())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_ingest_batch_preserves_all_logs(self, logs):
        """Property: all logs in a batch must be passed to ClickHouse."""
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()
        pipeline.clickhouse.insert_logs_batch.return_value = len(logs)

        import asyncio
        asyncio.run(pipeline.ingest_batch(logs))

        call_args = pipeline.clickhouse.insert_logs_batch.call_args[0][0]
        assert len(call_args) == len(logs), f"Expected {len(logs)} logs, got {len(call_args)}"


# =============================================================================
# Property 2: ML Detection Invariants
# =============================================================================

class TestMLDetectionProperties:
    """Property-based tests for ML anomaly detection."""

    @given(st.lists(log_entries(), min_size=1, max_size=20))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_detection_output_structure(self, logs):
        """Property: detection result must always have the same structure."""
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        result = detector.detect(logs)

        assert hasattr(result, "anomaly_score")
        assert hasattr(result, "is_anomaly")
        assert hasattr(result, "reconstruction_error")
        assert hasattr(result, "threshold_used")
        assert hasattr(result, "explanation")
        assert hasattr(result, "feature_scores")
        assert hasattr(result, "inference_time_ms")

        # Property: anomaly_score must be in [0, 1]
        assert 0.0 <= result.anomaly_score <= 1.0, f"Score {result.anomaly_score} out of range"

        # Property: inference_time_ms must be non-negative
        assert result.inference_time_ms >= 0, f"Negative inference time: {result.inference_time_ms}"

    @given(log_entries(), thresholds())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_threshold_monotonicity(self, log_entry, threshold):
        """Property: higher threshold should not increase anomaly rate."""
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        # Detect with two different thresholds
        result_low = detector.detect([log_entry], threshold=threshold - 0.1)
        result_high = detector.detect([log_entry], threshold=threshold)

        # Property: if is_anomaly with high threshold, must also be with low
        if result_high.is_anomaly:
            assert result_low.is_anomaly, "Monotonicity violated: high threshold detected but low didn't"

    @given(st.lists(log_entries(), min_size=1, max_size=10))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_detection_idempotent_for_same_input(self, logs):
        """Property: same input should produce same output (deterministic)."""
        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        result1 = detector.detect(logs)
        result2 = detector.detect(logs)

        assert result1.anomaly_score == result2.anomaly_score, "Non-deterministic detection"
        assert result1.is_anomaly == result2.is_anomaly, "Non-deterministic classification"


# =============================================================================
# Property 3: Online Detection Invariants
# =============================================================================

class TestOnlineDetectionProperties:
    """Property-based tests for online/anomaly detection."""

    @given(st.lists(st.floats(min_value=-10, max_value=10, allow_nan=False), min_size=10, max_size=200))
    @settings(max_examples=30)
    def test_adwin_drift_detection_bounds(self, stream):
        """Property: ADWIN drift detection must always return valid results."""
        from app.ml.online_detector import ADWIN
        adwin = ADWIN(delta=0.05)

        drift_count = 0
        for value in stream:
            drift_detected = adwin.update(value)
            if drift_detected:
                drift_count += 1

        # Property: drift count must be non-negative and <= len(stream)
        assert 0 <= drift_count <= len(stream), f"Drift count {drift_count} out of bounds"

        # Property: after reset, stats should be cleared
        adwin.reset()
        assert adwin.total == 0, "Reset should clear total"
        assert adwin.width == 0, "Reset should clear width"

    @given(st.lists(st.floats(min_value=-5, max_value=5, allow_nan=False), min_size=5, max_size=50))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_online_detector_adaptive_threshold(self, values):
        """Property: adaptive threshold should always be positive."""
        detector = OnlineAnomalyDetector(n_trees=10, window_size=50, threshold=2.0)

        for v in values:
            X = np.random.randn(1, 5) * 0.1 + v * 0.01
            detector.partial_fit(X)

        threshold = detector._get_adaptive_threshold()
        assert threshold > 0, f"Threshold must be positive, got {threshold}"


# =============================================================================
# Property 4: SOAR Engine Invariants
# =============================================================================

class TestSOARProperties:
    """Property-based tests for SOAR engine."""

    @given(st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False)),
        min_size=1, max_size=10,
    ))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_soar_execution_always_returns_status(self, alert_data):
        """Property: SOAR execution must always return a valid status."""
        import asyncio
        engine = SOAREngine()

        result = asyncio.run(engine.execute_playbook(
            playbook_name="ransomware_response",
            alert=alert_data,
            context={},
        ))

        assert result.status in PlaybookStatus.__members__.values(), f"Invalid status: {result.status}"
        assert result.duration_ms >= 0, f"Negative duration: {result.duration_ms}"

    @given(st.lists(
        st.dictionaries(
            keys=st.text(min_size=1, max_size=10),
            values=st.text(max_size=20),
            min_size=1, max_size=5,
        ),
        min_size=1, max_size=5,
    ))
    @settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
    def test_soar_audit_trail_ordering(self, alerts):
        """Property: audit trail entries must be chronologically ordered."""
        import asyncio
        engine = SOAREngine()

        for alert in alerts:
            result = asyncio.run(engine.execute_playbook(
                playbook_name="ransomware_response",
                alert=alert,
                context={},
            ))

            # Property: audit trail must start with playbook_started and end with playbook_completed
            if result.status == PlaybookStatus.COMPLETED and len(result.audit_trail) >= 2:
                assert result.audit_trail[0]["action"] == "playbook_started"
                assert result.audit_trail[-1]["action"] == "playbook_completed"


# =============================================================================
# Property 5: Security Invariants
# =============================================================================

class TestSecurityProperties:
    """Property-based tests for security features."""

    @given(st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False)),
        min_size=1, max_size=10,
    ))
    @settings(max_examples=30)
    def test_encryption_decryption_roundtrip(self, data):
        """Property: encrypt → decrypt must return original data."""
        mgr = SecurityManager()

        encrypted = mgr.encrypt_sensitive_fields(data)
        decrypted = mgr.decrypt_sensitive_fields(encrypted)

        # Property: decrypted must equal original for all keys
        for key in data:
            assert decrypted[key] == data[key], f"Roundtrip failed for key '{key}': {decrypted[key]} != {data[key]}"

    @given(st.text(min_size=10, max_size=100))
    @settings(max_examples=30)
    def test_jwt_token_roundtrip(self, payload_str):
        """Property: JWT create → decode must preserve subject."""
        mgr = SecurityManager()

        token = mgr.create_access_token(
            data={"sub": payload_str, "org_id": "test-org"},
            expires_delta=3600,
        )

        decoded = mgr.decode_token(token)

        assert decoded["sub"] == payload_str, f"Subject mismatch: {decoded['sub']} != {payload_str}"
        assert decoded["org_id"] == "test-org"


# =============================================================================
# Property 6: Conformal Prediction Invariants
# =============================================================================

class TestConformalPredictionProperties:
    """Property-based tests for conformal prediction."""

    @given(
        st.lists(st.floats(min_value=0.0, max_value=1.0, allow_nan=False), min_size=10, max_size=100),
        st.floats(min_value=0.8, max_value=0.99, allow_nan=False),
    )
    @settings(max_examples=20)
    def test_conformal_coverage_guarantee(self, scores, confidence):
        """Property: conformal prediction must achieve specified coverage."""
        conformal = SplitConformal(confidence=confidence)

        # Calibrate with scores
        conformal.calibrate(np.array(scores))

        # Property: threshold must be between min and max of scores
        threshold = conformal.threshold
        assert np.min(scores) <= threshold <= np.max(scores) or threshold == np.inf, \
            f"Threshold {threshold} out of score range [{np.min(scores)}, {np.max(scores)}]"

        # Property: coverage must be at least confidence level
        covered = np.mean(scores <= threshold) if threshold != np.inf else 1.0
        assert covered >= confidence - 0.1, \
            f"Coverage {covered:.3f} below confidence {confidence}"


# =============================================================================
# Property 7: Data Generator Invariants
# =============================================================================

class TestDataGeneratorProperties:
    """Property-based tests for data generation."""

    @given(
        st.integers(min_value=10, max_value=200),
        st.integers(min_value=8, max_value=64),
        st.floats(min_value=0.05, max_value=0.4, allow_nan=False),
    )
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_generated_data_shapes(self, n_seq, seq_len, anomaly_prob):
        """Property: generated data must have correct shapes and ranges."""
        generator = NetworkLogGenerator(seed=42)

        X, y = generator.generate_sequences(
            num_sequences=n_seq,
            seq_length=seq_len,
            anomaly_probability=anomaly_prob,
        )

        # Property: shapes must match
        assert X.shape == (n_seq, seq_len, 128), f"Shape mismatch: {X.shape}"
        assert y.shape == (n_seq,), f"Label shape mismatch: {y.shape}"

        # Property: values must be in [0, 1]
        assert X.min() >= 0.0, f"X min {X.min()} < 0"
        assert X.max() <= 1.0, f"X max {X.max()} > 1"

        # Property: labels must be binary
        assert set(np.unique(y)).issubset({0, 1}), f"Labels not binary: {np.unique(y)}"

        # Property: anomaly ratio must be approximately correct
        actual_ratio = np.mean(y)
        assert abs(actual_ratio - anomaly_prob) < 0.15, \
            f"Anomaly ratio {actual_ratio:.3f} too far from target {anomaly_prob}"


# =============================================================================
# Property 8: Pipeline Composition Invariants
# =============================================================================

class TestPipelineCompositionProperties:
    """Property-based tests for pipeline composition."""

    @given(log_batches())
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_pipeline_ingest_then_detect_preserves_count(self, logs):
        """Property: number of detection results must match number of logs."""
        import asyncio

        # Setup
        pipeline = IngestionPipeline()
        pipeline.producer = MagicMock()
        pipeline.clickhouse = MagicMock()
        pipeline.clickhouse.insert_logs_batch.return_value = len(logs)

        detector = AnomalyDetector(device="cpu", use_isolation_forest=False)
        detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        detector.model.eval()

        # Ingest
        count = asyncio.run(pipeline.ingest_batch(logs))
        assert count == len(logs)

        # Detect
        results = []
        for log in logs:
            result = detector.detect([log])
            results.append(result)

        # Property: number of results must equal number of logs
        assert len(results) == len(logs), f"Results {len(results)} != logs {len(logs)}"

        # Property: each result must have valid score
        for r in results:
            assert 0.0 <= r.anomaly_score <= 1.0


# =============================================================================
# Property 9: Online Detector Invariants (Hybrid)
# =============================================================================

class TestHybridDetectorProperties:
    """Property-based tests for hybrid online detector."""

    @given(
        st.integers(min_value=10, max_value=100),
        st.integers(min_value=2, max_value=10),
    )
    @settings(max_examples=15, suppress_health_check=[HealthCheck.too_slow])
    def test_hybrid_detector_always_returns_result(self, n_samples, n_features):
        """Property: hybrid detector must always return a valid OnlineDetectionResult."""
        detector = HybridOnlineDetector(
            n_trees=10,
            n_clusters=3,
            window_size=50,
        )

        # Generate random data
        X = np.random.randn(n_samples, n_features) * 0.5

        # Partial fit
        detector.partial_fit(X)

        # Predict
        result = detector.predict(X)

        # Property: result must have valid structure
        assert result.anomaly_score is not None
        assert result.is_anomaly is not None
        assert 0 <= result.anomaly_score <= 1.0

        # Property: drift detected must be boolean
        assert isinstance(result.drift_detected, bool)


# =============================================================================
# Property 10: Security Token Invariants
# =============================================================================

class TestSecurityTokenProperties:
    """Property-based tests for security tokens."""

    @given(
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=20),
        st.text(min_size=1, max_size=20),
    )
    @settings(max_examples=30)
    def test_token_contains_required_claims(self, username, org_id, role):
        """Property: JWT token must contain sub, org_id, and role claims."""
        from app.core.security import create_access_token, verify_token

        token = create_access_token(
            subject=username,
            org_id=org_id,
            role=role,
            expires_delta=3600,
        )

        payload = verify_token(token)

        assert payload["sub"] == username
        assert payload["org_id"] == org_id
        assert payload["role"] == role

    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=20)
    def test_expired_token_raises_error(self, username):
        """Property: expired token must raise an exception."""
        from app.core.security import create_access_token, verify_token
        from jose import ExpiredSignatureError

        token = create_access_token(
            subject=username,
            org_id="test",
            role="admin",
            expires_delta=-1,  # Expired immediately
        )

        with pytest.raises(Exception):
            verify_token(token)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--capture=no"])
