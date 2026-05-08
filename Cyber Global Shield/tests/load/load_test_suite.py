"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Load Test Suite                      ║
║  Tests de charge automatisés avec Locust                    ║
║  Simule 10 000 utilisateurs simultanés                      ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    # Lancer les tests de charge
    locust -f tests/load/load_test_suite.py --host=http://localhost:8000
    
    # Mode headless (CI/CD)
    locust -f tests/load/load_test_suite.py --host=http://localhost:8000 \
        --headless -u 1000 -r 100 --run-time 5m --csv=results/load_test
    
    # Avec authentification
    locust -f tests/load/load_test_suite.py --host=http://localhost:8000 \
        --headless -u 500 -r 50 --run-time 10m \
        --csv=results/load_test --html=results/load_test_report.html
"""

import os
import json
import random
import time
from typing import Dict, Any, Optional
from datetime import datetime

from locust import HttpUser, task, between, constant, events, SequentialTaskSet
from locust.runners import MasterRunner, WorkerRunner
import gevent


# =============================================================================
# Configuration
# =============================================================================

# Simulation de données réalistes
MALICIOUS_IPS = [
    "45.33.32.156", "185.220.101.42", "91.121.87.28",
    "51.75.144.253", "192.168.1.100", "10.0.0.50",
]

LEGITIMATE_IPS = [
    f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    for _ in range(100)
]

EVENT_TYPES = [
    "connection", "dns", "http", "ssl", "dhcp",
    "smb", "kerberos", "rdp", "ssh", "ftp",
]

SEVERITIES = ["info", "warning", "error", "critical"]

THREAT_TYPES = [
    "ransomware_activity", "data_exfiltration", "brute_force",
    "malware_detected", "phishing_attempt", "ddos_attack",
    "unauthorized_access", "privilege_escalation", "lateral_movement",
    "command_and_control",
]

PLAYBOOKS = [
    "ransomware_response", "phishing_response", "brute_force_response",
    "data_exfiltration_response", "malware_response", "ddos_mitigation",
]


# =============================================================================
# Test Data Generator
# =============================================================================

class TestDataGenerator:
    """Génère des données de test réalistes."""

    @staticmethod
    def generate_log_entry() -> Dict[str, Any]:
        """Generate a realistic log entry."""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": random.choice(MALICIOUS_IPS + LEGITIMATE_IPS),
            "dst_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 3389, 445, 53, 8080]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "event_type": random.choice(EVENT_TYPES),
            "severity": random.choices(
                SEVERITIES,
                weights=[0.6, 0.25, 0.1, 0.05],  # 5% critical
            )[0],
            "bytes_sent": random.randint(64, 65536),
            "bytes_received": random.randint(64, 65536),
            "duration": round(random.uniform(0.001, 60.0), 3),
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "curl/7.68.0", "Python-urllib/3.11",
            ]),
        }

    @staticmethod
    def generate_alert() -> Dict[str, Any]:
        """Generate a realistic security alert."""
        src_ip = random.choice(MALICIOUS_IPS)
        return {
            "event_type": random.choice(THREAT_TYPES),
            "src_ip": src_ip,
            "dst_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "severity": random.choices(
                ["low", "medium", "high", "critical"],
                weights=[0.3, 0.4, 0.2, 0.1],
            )[0],
            "confidence": round(random.uniform(0.5, 0.99), 2),
            "description": f"Detected {random.choice(THREAT_TYPES)} from {src_ip}",
            "mitre_attack_id": random.choice([
                "T1486", "T1567", "T1110", "T1204", "T1566",
                "T1498", "T1078", "T1068", "T1021", "T1041",
            ]),
            "iocs": {
                "ips": [src_ip],
                "domains": [f"malicious{random.randint(1, 100)}.xyz"],
                "hashes": [f"a" * 64],
            },
        }

    @staticmethod
    def generate_playbook_request() -> Dict[str, Any]:
        """Generate a playbook execution request."""
        alert = TestDataGenerator.generate_alert()
        return {
            "playbook_name": random.choice(PLAYBOOKS),
            "alert": alert,
            "iocs": alert["iocs"],
            "auto_approve": random.random() > 0.3,  # 70% auto-approve
        }


# =============================================================================
# User Behaviors
# =============================================================================

class SOCAnalystBehavior(SequentialTaskSet):
    """
    Simule le comportement d'un analyste SOC.
    Séquence réaliste d'actions.
    """

    def on_start(self):
        """Login and get token."""
        self.token = None
        self.org_id = "global"

    @task
    def login(self):
        """Authenticate."""
        with self.client.post(
            "/api/v1/auth/login",
            json={
                "username": f"analyst_{random.randint(1, 100)}",
                "password": "test_password",
            },
            catch_response=True,
            name="POST /auth/login",
        ) as response:
            if response.status_code == 200:
                try:
                    data = response.json()
                    self.token = data.get("access_token", "")
                except:
                    pass

    @task(10)
    def view_dashboard(self):
        """View security dashboard."""
        self.client.get(
            f"/api/v1/dashboard/summary?org_id={self.org_id}",
            headers=self._get_headers(),
            name="GET /dashboard/summary",
        )

    @task(8)
    def view_alerts(self):
        """View security alerts."""
        self.client.get(
            f"/api/v1/dashboard/alerts?org_id={self.org_id}&severity=critical&limit=50",
            headers=self._get_headers(),
            name="GET /dashboard/alerts",
        )

    @task(5)
    def view_threat_map(self):
        """View threat map."""
        self.client.get(
            "/apps/web/threat_map.html",
            name="GET /threat_map",
        )

    @task(3)
    def investigate_alert(self):
        """Investigate an alert with AI agent."""
        alert = TestDataGenerator.generate_alert()
        self.client.post(
            "/api/v1/agents/investigate",
            json={
                "alert": alert,
                "logs": [TestDataGenerator.generate_log_entry() for _ in range(5)],
            },
            headers=self._get_headers(),
            name="POST /agents/investigate",
        )

    @task(2)
    def execute_playbook(self):
        """Execute SOAR playbook."""
        request = TestDataGenerator.generate_playbook_request()
        self.client.post(
            "/api/v1/soar/execute",
            json=request,
            headers=self._get_headers(),
            name="POST /soar/execute",
        )

    @task(1)
    def get_analytics(self):
        """Get security analytics."""
        self.client.get(
            f"/api/v1/security/dashboard/analytics?org_id={self.org_id}&hours=24",
            headers=self._get_headers(),
            name="GET /dashboard/analytics",
        )

    @task(1)
    def export_report(self):
        """Export security report."""
        self.client.get(
            f"/api/v1/security/export?format=pdf&org_id={self.org_id}",
            headers=self._get_headers(),
            name="GET /export/pdf",
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get auth headers."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


class DataIngestionBehavior(HttpUser):
    """
    Simule l'ingestion massive de logs.
    Charge élevée : 100 req/s par utilisateur.
    """

    wait_time = constant(0.01)  # 100 requests per second
    host = "http://localhost:8000"

    @task(20)
    def ingest_log(self):
        """Ingest a log entry."""
        log = TestDataGenerator.generate_log_entry()
        self.client.post(
            "/api/v1/ingestion/log",
            json=log,
            name="POST /ingestion/log",
        )

    @task(5)
    def ingest_batch(self):
        """Ingest a batch of logs."""
        batch = [TestDataGenerator.generate_log_entry() for _ in range(100)]
        self.client.post(
            "/api/v1/ingestion/batch",
            json={"logs": batch},
            name="POST /ingestion/batch",
        )

    @task(1)
    def ingest_alert(self):
        """Ingest a security alert."""
        alert = TestDataGenerator.generate_alert()
        self.client.post(
            "/api/v1/ingestion/alert",
            json=alert,
            name="POST /ingestion/alert",
        )


class MLInferenceBehavior(HttpUser):
    """
    Simule les appels aux modèles ML.
    Charge modérée : 10 req/s par utilisateur.
    """

    wait_time = constant(0.1)  # 10 requests per second

    @task(10)
    def anomaly_detection(self):
        """Run anomaly detection."""
        features = {
            "features": [random.random() for _ in range(10)],
            "model": random.choice(["isolation_forest", "autoencoder", "quantum"]),
        }
        self.client.post(
            "/api/v1/ml/detect",
            json=features,
            name="POST /ml/detect",
        )

    @task(3)
    def threat_prediction(self):
        """Run threat prediction."""
        self.client.post(
            "/api/v1/ml/predict",
            json={
                "features": [random.random() for _ in range(20)],
                "model": "attack_predictor",
            },
            name="POST /ml/predict",
        )

    @task(1)
    def quantum_detection(self):
        """Run quantum anomaly detection."""
        self.client.post(
            "/api/v1/ml/quantum/detect",
            json={
                "data": [random.random() for _ in range(8)],
                "n_qubits": 4,
            },
            name="POST /ml/quantum/detect",
        )


class APIExplorationBehavior(HttpUser):
    """
    Simule l'exploration de l'API par un développeur.
    Charge légère : 1 req/s par utilisateur.
    """

    wait_time = between(0.5, 2.0)

    @task(5)
    def health_check(self):
        """Check API health."""
        self.client.get("/health", name="GET /health")

    @task(3)
    def get_metrics(self):
        """Get Prometheus metrics."""
        self.client.get("/metrics", name="GET /metrics")

    @task(2)
    def list_endpoints(self):
        """List API endpoints."""
        self.client.get("/docs", name="GET /docs")

    @task(1)
    def get_openapi(self):
        """Get OpenAPI spec."""
        self.client.get("/openapi.json", name="GET /openapi.json")


# =============================================================================
# Event Handlers
# =============================================================================

@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """Initialize load test environment."""
    if isinstance(environment.runner, MasterRunner):
        print("""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Load Test Suite                      ║
║                                                              ║
║  📊 Scénarios de test :                                      ║
║     • SOC Analyst : Dashboard, Alertes, Investigation, SOAR  ║
║     • Data Ingestion : 100 req/s logs, batch, alerts         ║
║     • ML Inference : Détection, Prédiction, Quantum          ║
║     • API Exploration : Health, Metrics, Documentation       ║
║                                                              ║
║  🎯 Objectifs :                                              ║
║     • 10 000 req/s soutenus                                  ║
║     • P99 latence < 500ms                                    ║
║     • 0% d'erreurs 5xx                                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test start."""
    print(f"\n🚀 Load test started at {datetime.utcnow().isoformat()}")
    print(f"   Target: {environment.host}")
    print(f"   Users: {environment.runner.target_user_count}")
    print(f"   Spawn rate: {environment.runner.spawn_rate}/s\n")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Log test stop."""
    stats = environment.runner.stats
    print(f"\n📊 Load test completed at {datetime.utcnow().isoformat()}")
    print(f"   Total requests: {stats.total_num_requests}")
    print(f"   Total failures: {stats.total_num_failures}")
    print(f"   Avg response time: {stats.avg_response_time:.2f}ms")
    print(f"   P95 response time: {stats.get_response_time_percentile(0.95):.2f}ms")
    print(f"   P99 response time: {stats.get_response_time_percentile(0.99):.2f}ms")
    print(f"   Current RPS: {stats.current_rps:.2f}")
    print(f"   Fail ratio: {stats.total_num_failures / max(stats.total_num_requests, 1) * 100:.2f}%\n")


# =============================================================================
# Main entry point for direct execution
# =============================================================================

if __name__ == "__main__":
    import subprocess
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    users = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    spawn_rate = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    run_time = sys.argv[4] if len(sys.argv) > 4 else "5m"

    cmd = [
        "locust",
        "-f", __file__,
        "--host", host,
        "--headless",
        "-u", str(users),
        "-r", str(spawn_rate),
        "--run-time", run_time,
        "--csv", f"results/load_test_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        "--html", f"results/load_test_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html",
    ]

    print(f"🚀 Starting load test: {users} users, {spawn_rate}/s spawn, {run_time} duration")
    subprocess.run(cmd)
