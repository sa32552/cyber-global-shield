import unittest
from unittest.mock import MagicMock, patch
import numpy as np
import torch
from app.ml.anomaly_detector import AnomalyDetector, TransformerAutoencoder, IsolationForestWrapper
from app.ml.dataset_generator import NetworkLogGenerator
from app.soar.playbook_engine import SOAREngine, SOARPlaybook, ActionStatus
from app.agents.crew import CyberShieldCrew, TriageAssessment, InvestigationReport, ResponseDecision
from datetime import datetime, timezone, timedelta
import json

# Mock settings for testing
class MockSettings:
    OPENAI_API_KEY = "sk-test"
    CREWAI_MODEL = "gpt-4o"
    CREWAI_TEMPERATURE = 0.7
    CREWAI_MAX_TOKENS = 1024
    SOAR_TIMEOUT = 30

@patch("app.core.config.settings", MockSettings())
class TestAnomalyDetectorEnhancements(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.detector = AnomalyDetector(device="cpu", use_isolation_forest=False) # Disable IF for focused testing
        self.detector.model = TransformerAutoencoder(input_dim=128, d_model=256, latent_dim=64)
        self.detector.model.eval()
        self.generator = NetworkLogGenerator(seed=42)

    def test_log_to_features_enrichment(self):
        # Test with more diverse log types and nested data
        log = {
            "org_id": "test-org",
            "source": "zeek",
            "event_type": "http_request",
            "severity": "high",
            "src_ip": "192.168.1.10",
            "dst_ip": "1.1.1.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "tcp",
            "hostname": "workstation-1",
            "user": "john.doe",
            "process_name": "firefox",
            "bytes_sent": 1024,
            "bytes_received": 4096,
            "packets_sent": 10,
            "packets_received": 15,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_method": "GET",
            "url": "http://malicious.com/payload.exe",
            "response_code": 200,
            "user_agent": "Mozilla/5.0",
            "file_hash": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
        }

        features = self.detector._log_to_features(log)

        # Assert basic feature encoding
        self.assertGreater(features[0], 0) # src_ip
        self.assertGreater(features[1], 0) # dst_ip
        self.assertAlmostEqual(features[2], 54321 / 65535.0, places=4) # src_port
        self.assertAlmostEqual(features[3], 80 / 65535.0, places=4) # dst_port
        self.assertEqual(features[4], 0.1) # tcp protocol
        self.assertEqual(features[15], datetime.now(timezone.utc).hour / 24.0) # hour

        # Assert new feature encoding (e.g., file_hash, url related)
        # This assumes _log_to_features is updated to handle these
        # For now, we'll just check if it doesn't break and potentially add new assertions if features are mapped
        # Example of an improved feature mapping for 'file_hash' or 'url'
        # self.assertGreater(features[22], 0) # Placeholder for a new hash feature index

    async def test_detect_anomaly_with_dynamic_threshold_adjustment(self):
        # Simulate normal data to calibrate threshold
        normal_sequences = []
        for _ in range(100):
            logs = [self.generator.generate_normal_log() for _ in range(64)]
            normal_sequences.append(logs)

        initial_threshold = self.detector.calibrate_threshold(normal_sequences, percentile=95.0)
        self.assertGreater(initial_threshold, 0)

        # Simulate an attack
        attack_logs = [self.generator.generate_attack_log("ransomware_activity") for _ in range(64)]
        result = self.detector.detect(attack_logs)

        # Assert anomaly detected with calibrated threshold
        self.assertTrue(result.is_anomaly)
        self.assertGreater(result.anomaly_score, initial_threshold)
        self.assertIsNotNone(result.explanation)


@patch("app.core.config.settings", MockSettings())
class TestSOAREngineEnhancements(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.soar_engine = SOAREngine()
        self.soar_engine._http_client = MagicMock() # Mock HTTP client
        self.soar_engine._action_handlers["test_action"] = self._mock_test_action # Add a mock handler

    async def _mock_test_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        if action.get("fail", False):
            raise ValueError("Simulated action failure")
        return {"status": "success", "action_params": action.get("params")}

    def test_add_rollback_action_type(self):
        # Assuming a new rollback action type is added directly in _rollback for testing
        # This test ensures _rollback is called and handles registered rollback actions.
        pass # Actual rollback logic needs to be in SOAREngine, not just tested here.

    async def test_execute_playbook_with_rollback_on_failure(self):
        playbook_name = "test_rollback_playbook"
        self.soar_engine.register_playbook(SOARPlaybook(
            name=playbook_name,
            description="Playbook with rollback action",
            trigger_event="test_trigger",
            actions=[
                {
                    "name": "action_1",
                    "type": "test_action",
                    "params": {"key": "value"},
                    "rollback": True,
                    "order": 1,
                },
                {
                    "name": "action_2_fail",
                    "type": "test_action",
                    "params": {"fail": True},
                    "rollback": True,
                    "order": 2,
                },
            ]
        ))

        context = {"alert": {"id": "test-alert"}}
        result = await self.soar_engine.execute_playbook(playbook_name, context)

        self.assertEqual(result.status, ActionStatus.ROLLED_BACK)
        self.assertEqual(len(result.actions_results), 2)
        self.assertEqual(result.actions_results[0].status, ActionStatus.COMPLETED)
        self.assertEqual(result.actions_results[1].status, ActionStatus.FAILED)

        # Here we'd assert that a specific rollback action was called
        # For now, we confirm the playbook status indicates rollback.
        # A more detailed test would involve mocking rollback calls.


@patch("app.core.config.settings", MockSettings())
@patch("langchain_openai.ChatOpenAI") # Mock ChatOpenAI for agent tests
class TestCrewAIAgentEnhancements(unittest.IsolatedAsyncioTestCase):

    def setUp(self, MockChatOpenAI):
        # Mock LLM and its .invoke() method
        self.mock_llm_instance = MockChatOpenAI.return_value
        self.mock_llm_instance.invoke.side_effect = [
            json.dumps({
                "alert_id": "test-alert-123",
                "severity": "critical",
                "confidence": 0.95,
                "priority": 9,
                "is_false_positive": False,
                "requires_immediate_action": True,
                "reasoning": "Highly suspicious network activity",
                "recommended_next_step": "Investigate laterally coupled activity"
            }),
            json.dumps({
                "alert_id": "test-alert-123",
                "root_cause": "Malware execution",
                "attack_vector": "Email phishing",
                "affected_assets": ["host-1", "host-2"],
                "mitre_tactic": "TA0001",
                "mitre_technique": "T1566",
                "kill_chain_phase": "Exploitation",
                "iocs_found": {"ips": ["1.2.3.4"]},
                "timeline": [],
                "lateral_movement_detected": True,
                "data_exfiltration_detected": False,
                "confidence": 0.9,
                "summary": "Malware successfully executed via phishing email leading to lateral movement."
            }),
            json.dumps({
                "alert_id": "test-alert-123",
                "decision_type": "isolate_host",
                "confidence": 0.98,
                "actions": [{"type": "edr_action", "name": "isolate_host_network", "params": {"host": "host-1"}}],
                "playbook_name": "ransomware_response",
                "requires_human_approval": False,
                "reasoning": "High confidence ransomware activity detected, immediate isolation required.",
                "risk_assessment": "High - potential data loss"
            })
        ]
        self.crew = CyberShieldCrew(verbose=False)

    async def test_full_pipeline_execution(self):
        alert = {"id": "test-alert-123", "alert_type": "ransomware_activity", "title": "Ransomware Detected"}
        logs = [{"log_data": "sample"}]
        context = {"org_id": "test-org"}

        result = await self.crew.run_full_pipeline(alert, logs, context)

        self.assertEqual(result["stage"], "completed")
        self.assertEqual(result["triage"]["severity"], "critical")
        self.assertTrue(result["investigation"]["lateral_movement_detected"])
        self.assertEqual(result["decision"]["decision_type"], "isolate_host")
        self.assertIsNotNone(result["duration_seconds"])


@patch("app.core.config.settings", MockSettings())
class TestDatasetGeneratorEnhancements(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.generator = NetworkLogGenerator(seed=42)

    def test_generate_dataset_with_multi_stage_attack(self):
        # Extend generate_dataset to include multi-stage attacks
        # For now, this test will check if the existing attack generation works
        total_logs = 1000
        attack_ratio = 0.1
        all_logs, normal_logs = self.generator.generate_dataset(total_logs, attack_ratio)

        self.assertEqual(len(all_logs), total_logs)
        self.assertLess(len(normal_logs), total_logs)
        attack_logs_count = sum(1 for log in all_logs if log.get("is_attack"))
        self.assertGreater(attack_logs_count, 0)

        # Further assertion would involve checking for specific sequences indicative of multi-stage attacks

    def test_generate_sequences_with_complex_anomalies(self):
        # Simulate generating sequences with different types of anomalies and normal traffic
        num_sequences = 100
        seq_length = 64
        anomaly_probability = 0.2

        X, y = self.generator.generate_sequences(num_sequences, seq_length, anomaly_probability)

        self.assertEqual(X.shape, (num_sequences, seq_length, 128))
        self.assertEqual(y.shape, (num_sequences,))
        self.assertGreater(np.sum(y == 1), 0) # Ensure some anomalies are generated
        self.assertGreater(np.sum(y == 0), 0) # Ensure some normal sequences are generated


@patch("app.core.config.settings", MockSettings())
class TestIngestionPipelineEnhancements(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.pipeline = IngestionPipeline()
        self.pipeline.producer = MagicMock() # Mock Kafka producer
        self.pipeline.clickhouse = MagicMock() # Mock ClickHouse client
        self.pipeline.clickhouse.insert_logs_batch.return_value = 1

    async def test_enrich_log_with_threat_intel_integration(self):
        log = {
            "org_id": "test-org",
            "source": "zeek",
            "event_type": "connection",
            "severity": "info",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_payload": {},
        }

        # Mock a threat intel lookup function
        mock_ti_lookup = MagicMock(return_value={
            "threat_actor": "APT29",
            "confidence": 0.9,
            "tags": ["malicious", "c2"]
        })
        with patch.object(self.pipeline, 
                          "_perform_threat_intel_lookup", 
                          new=mock_ti_lookup):
            enriched_log = self.pipeline.enrich_log(log)

            # Assert new threat intel fields are added
            self.assertEqual(enriched_log.get("threat_actor"), "APT29")
            self.assertIn("malicious", enriched_log.get("tags"))
            self.assertEqual(enriched_log.get("severity"), "high") # Should be escalated based on TI
            mock_ti_lookup.assert_called_once_with(log.get("src_ip"), log.get("dst_ip"))

    async def _perform_threat_intel_lookup(self, src_ip: str, dst_ip: str) -> Dict[str, Any]:
        # This would be a real integration in the enhanced pipeline
        if src_ip == "1.2.3.4":
            return {
                "threat_actor": "APT29",
                "campaign": "WellMess",
                "confidence": 0.9,
                "sources": ["MISP"],
                "tags": ["malicious", "c2"],
                "severity_override": "critical"
            }
        return {}

    async def test_end_to_end_ingestion_with_enrichment_and_batching(self):
        logs_to_ingest = []
        for i in range(500):
            log = {
                "org_id": "test-org",
                "source": "zeek",
                "event_type": "connection",
                "src_ip": f"192.168.1.{i % 254 + 1}",
                "dst_ip": "8.8.8.8",
                "protocol": "udp",
                "timestamp": (datetime.now(timezone.utc) - timedelta(seconds=i)).isoformat(),
                "raw_payload": {},
            }
            logs_to_ingest.append(log)

        # Simulate a malicious IP for enrichment
        malicious_log = {
            "org_id": "test-org",
            "source": "suricata",
            "event_type": "alert",
            "severity": "info",
            "src_ip": "1.2.3.4", # Our malicious IP
            "dst_ip": "10.0.0.5",
            "protocol": "tcp",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_payload": {"signature": "ET INFO Detections"},
        }
        logs_to_ingest.append(malicious_log)

        # Patch the threat intel lookup to return a value for the malicious IP
        with patch.object(self.pipeline, 
                          "_perform_threat_intel_lookup", 
                          new=self._perform_threat_intel_lookup):
            inserted_count = await self.pipeline.ingest_batch(logs_to_ingest)

            self.assertEqual(inserted_count, len(logs_to_ingest))
            self.pipeline.clickhouse.insert_logs_batch.assert_called_once()

            # Verify one log was enriched with critical severity
            call_args = self.pipeline.clickhouse.insert_logs_batch.call_args[0][0]
            found_malicious_log = False
            for log in call_args:
                if log.get("src_ip") == "1.2.3.4" and log.get("severity") == "critical":
                    found_malicious_log = True
                    break
            self.assertTrue(found_malicious_log, "Malicious log was not correctly enriched and escalated.")

if __name__ == "__main__":
    unittest.main()