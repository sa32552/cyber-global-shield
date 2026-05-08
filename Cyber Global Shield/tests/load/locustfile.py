"""
Cyber Global Shield — Load Testing with Locust
Test de charge pour valider les performances de la plateforme.

Usage: locust -f tests/load/locustfile.py --host=http://localhost:8000
"""

import random
import json
from locust import HttpUser, task, between, constant


class SOCAnalystUser(HttpUser):
    """
    Simulates a SOC analyst browsing the dashboard and viewing data.
    """
    wait_time = between(1, 5)
    token = None

    def on_start(self):
        """Login and get token."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "analyst@test.com",
                "password": "test_password_123",
            },
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("access_token", "")
            self.client.headers.update({
                "Authorization": f"Bearer {self.token}",
                "X-Org-ID": "org_demo",
            })

    @task(3)
    def view_dashboard(self):
        """View main dashboard stats."""
        self.client.get("/api/v1/dashboard/stats")
        self.client.get("/api/v1/dashboard/alerts/recent")

    @task(2)
    def view_logs(self):
        """Browse logs with pagination."""
        page = random.randint(1, 10)
        self.client.get(f"/api/v1/logs?page={page}&page_size=50")

    @task(2)
    def view_alerts(self):
        """Browse alerts."""
        page = random.randint(1, 5)
        self.client.get(f"/api/v1/alerts?page={page}&page_size=20")

    @task(1)
    def view_anomalies(self):
        """View ML anomalies."""
        self.client.get("/api/v1/ml/anomalies/recent")

    @task(1)
    def view_threat_map(self):
        """View threat map data."""
        self.client.get("/api/v1/threats/map")

    @task(1)
    def search_logs(self):
        """Search through logs."""
        search_terms = ["192.168.", "10.0.", "ssh", "http", "blocked"]
        term = random.choice(search_terms)
        self.client.get(f"/api/v1/logs/search?q={term}&page=1")

    @task(1)
    def export_logs(self):
        """Export logs as CSV."""
        self.client.get("/api/v1/logs/export/csv?limit=100")

    @task(1)
    def get_ml_stats(self):
        """Get ML model statistics."""
        self.client.get("/api/v1/ml/stats")

    @task(1)
    def get_soar_playbooks(self):
        """List SOAR playbooks."""
        self.client.get("/api/v1/soar/playbooks")

    @task(1)
    def get_notifications(self):
        """Get notifications."""
        self.client.get("/api/v1/notifications?limit=20")


class MLTrainingUser(HttpUser):
    """
    Simulates ML model training operations.
    """
    wait_time = between(10, 30)
    token = None

    def on_start(self):
        """Login as admin."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin@test.com",
                "password": "admin_password_123",
            },
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("access_token", "")
            self.client.headers.update({
                "Authorization": f"Bearer {self.token}",
                "X-Org-ID": "org_demo",
            })

    @task(1)
    def trigger_training(self):
        """Trigger model training."""
        self.client.post("/api/v1/ml/train", json={
            "epochs": 10,
            "batch_size": 32,
        })

    @task(2)
    def check_training_status(self):
        """Check training status."""
        self.client.get("/api/v1/ml/training/status")

    @task(1)
    def get_model_metrics(self):
        """Get model performance metrics."""
        self.client.get("/api/v1/ml/metrics")

    @task(1)
    def deploy_model(self):
        """Deploy a model version."""
        self.client.post("/api/v1/ml/deploy", json={
            "model_version": "latest",
        })


class SOARUser(HttpUser):
    """
    Simulates SOAR playbook execution.
    """
    wait_time = between(5, 15)
    token = None

    def on_start(self):
        """Login as admin."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin@test.com",
                "password": "admin_password_123",
            },
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("access_token", "")
            self.client.headers.update({
                "Authorization": f"Bearer {self.token}",
                "X-Org-ID": "org_demo",
            })

    @task(1)
    def execute_playbook(self):
        """Execute a SOAR playbook."""
        self.client.post("/api/v1/soar/execute", json={
            "playbook_id": "block_malicious_ip",
            "params": {
                "ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "reason": "Load test execution",
            },
        })

    @task(2)
    def list_executions(self):
        """List recent playbook executions."""
        self.client.get("/api/v1/soar/executions?limit=20")

    @task(1)
    def get_playbook_stats(self):
        """Get SOAR statistics."""
        self.client.get("/api/v1/soar/stats")


class WebSocketUser(HttpUser):
    """
    Simulates WebSocket connections for real-time updates.
    """
    wait_time = between(1, 3)

    @task
    def websocket_connect(self):
        """Connect to WebSocket for real-time updates."""
        # WebSocket testing is limited in Locust
        # This simulates the HTTP upgrade request
        self.client.get("/ws")


# Test scenarios configuration
class LoadTestConfig:
    """Configuration for load tests."""
    USERS = {
        "soc_analysts": 50,  # 50 concurrent SOC analysts
        "ml_trainers": 5,    # 5 concurrent ML trainers
        "soar_users": 10,    # 10 concurrent SOAR users
        "websocket_users": 20,  # 20 concurrent WebSocket users
    }
    SPAWN_RATE = 10  # Users spawned per second
    DURATION = "10m"  # Test duration
    HOST = "http://localhost:8000"

    # Performance targets
    TARGETS = {
        "p95_response_time_ms": 500,  # 95% of requests under 500ms
        "error_rate_percent": 1,      # Less than 1% errors
        "requests_per_second": 1000,  # 1000 RPS minimum
    }
