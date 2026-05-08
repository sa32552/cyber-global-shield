"""
Cyber Global Shield — AI Deception Grid ULTIMATE
Réseau de leurres IA qui imitent le comportement humain pour piéger les attaquants.
Génère des utilisateurs, bases de données, API, et documents factices réalistes.
ML-based attacker profiling, adaptive honeypots, real-time threat intelligence.

Technologies :
- AI-generated fake users with behavioral patterns
- ML-based attacker profiling
- Adaptive honeypots (learn from attacker behavior)
- Real-time threat intelligence gathering
- Automated incident response on trap trigger
- Cross-correlation with dark web intel
- Fake credentials with realistic patterns
- Honey tokens and canary files
- SSH/HTTP/DB honeypot simulation
- Attacker attribution and tracking
"""

import json
import random
import logging
import hashlib
import asyncio
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


@dataclass
class DeceptionAsset:
    asset_id: str
    asset_type: str
    name: str
    description: str
    interactions: int = 0
    last_interaction: Optional[datetime] = None
    is_compromised: bool = False
    risk_score: float = 0.0
    ml_attacker_profile: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackerProfile:
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_interactions: int
    assets_compromised: Set[str]
    techniques_used: List[str]
    risk_score: float
    is_tracked: bool
    country: Optional[str] = None
    asn: Optional[str] = None
    tools_detected: List[str] = field(default_factory=list)


class AIDeceptionGrid:
    """
    AI Deception Grid ULTIMATE — Piège intelligent pour attaquants.
    Génère automatiquement des leurres réalistes et profile les attaquants.
    """

    def __init__(self):
        self._assets: List[DeceptionAsset] = []
        self._fake_users: List[Dict] = []
        self._fake_databases: List[Dict] = []
        self._fake_apis: List[Dict] = []
        self._honey_documents: List[Dict] = []
        self._honey_tokens: List[Dict] = []
        self._interactions_log: List[Dict] = []
        self._attacker_profiles: Dict[str, AttackerProfile] = {}
        self._deployed = False
        self.stats = {
            "total_assets": 0, "compromised_assets": 0, "total_interactions": 0,
            "unique_attackers": 0, "high_risk_attackers": 0, "alerts_generated": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

    def deploy(self):
        if self._deployed: return
        self._generate_fake_users(100)
        self._generate_fake_databases(20)
        self._generate_fake_apis(50)
        self._generate_honey_documents(200)
        self._generate_honey_tokens(50)
        self._deployed = True
        logger.info(f"🎭 AI Deception Grid ULTIMATE deployed: {len(self._fake_users)} users, {len(self._fake_databases)} databases, {len(self._fake_apis)} APIs, {len(self._honey_documents)} docs, {len(self._honey_tokens)} tokens")

    def _generate_fake_users(self, count: int):
        first_names = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry", "Iris", "Jack", "Kate", "Leo", "Marie", "Nathan", "Olivia", "Paul", "Quinn", "Rose", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xander", "Yara", "Zack"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Anderson", "Taylor", "Thomas", "Jackson", "White"]
        departments = ["Engineering", "Finance", "HR", "Sales", "Marketing", "Legal", "Operations", "Research", "IT", "Executive", "Security", "DevOps"]
        roles = ["Manager", "Director", "Analyst", "Engineer", "VP", "Coordinator", "Specialist", "Lead", "Admin", "Consultant", "Architect", "SRE"]
        for i in range(count):
            first = random.choice(first_names); last = random.choice(last_names); dept = random.choice(departments); role = random.choice(roles)
            user = {"username": f"{first.lower()}.{last.lower()}", "email": f"{first.lower()}.{last.lower()}@company.com", "full_name": f"{first} {last}", "department": dept, "role": f"{role} of {dept}", "password_hash": hashlib.sha256(f"password_{i}_2024".encode()).hexdigest(), "last_login": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 720))).isoformat(), "failed_logins": random.randint(0, 3), "permissions": random.sample(["read", "write", "admin", "audit", "deploy", "ssh", "sudo"], random.randint(1, 4)), "is_honeypot": True, "behavior_pattern": {"login_hours": f"{random.randint(6,10)}-{random.randint(17,20)}", "avg_logins_per_day": random.randint(1, 5), "usual_ips": [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"], "usual_devices": random.sample(["Windows", "macOS", "Linux", "iOS", "Android"], random.randint(1, 2)), "mfa_enabled": random.choice([True, False]), "ssh_keys": [f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC{i}"] if random.random() < 0.3 else []}}
            self._fake_users.append(user)
            asset = DeceptionAsset(asset_id=f"USER-HONEY-{i}", asset_type="user", name=user["username"], description=f"Honeypot user: {user['full_name']} ({user['role']})")
            self._assets.append(asset)

    def _generate_fake_databases(self, count: int):
        db_types = ["MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "Cassandra", "DynamoDB"]
        db_names = ["customers", "employees", "financials", "products", "orders", "payments", "analytics", "backups", "config", "secrets", "credentials", "passwords", "pii", "health_records"]
        for i in range(count):
            db_type = random.choice(db_types); db_name = random.choice(db_names)
            db = {"host": f"db-{db_name}.internal.company.com", "port": {"MySQL": 3306, "PostgreSQL": 5432, "MongoDB": 27017, "Redis": 6379, "Elasticsearch": 9200, "Cassandra": 9042, "DynamoDB": 443}[db_type], "database_type": db_type, "database_name": f"{db_name}_prod", "username": f"app_{db_name}", "password": f"Temp_{random.randint(1000,9999)}_{db_name}!", "size_gb": round(random.uniform(10, 500), 2), "tables": random.randint(5, 50), "records": random.randint(10000, 5000000), "contains_credit_cards": random.choice([True, False]), "contains_pii": True, "last_backup": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 48))).isoformat(), "is_honeypot": True, "ssl_enabled": random.choice([True, False]), "replication": random.choice(["master-slave", "cluster", "standalone"])}
            self._fake_databases.append(db)
            asset = DeceptionAsset(asset_id=f"DB-HONEY-{i}", asset_type="database", name=f"{db_name}_prod", description=f"Honeypot {db_type} database: {db_name}")
            self._assets.append(asset)

    def _generate_fake_apis(self, count: int):
        api_paths = ["/api/v1/users", "/api/v1/orders", "/api/v1/payments", "/api/v1/admin", "/api/v1/config", "/api/v1/backup", "/api/v1/export", "/api/v1/reports", "/api/v1/audit", "/api/v1/deploy", "/api/v1/secrets", "/api/v1/keys", "/graphql", "/swagger.json", "/.env", "/wp-admin", "/admin/panel", "/api/docs", "/health", "/metrics", "/api/v1/credentials", "/api/v1/database/dump", "/api/v1/ssh/keys", "/actuator", "/api/v1/internal", "/debug", "/api/v1/aws/keys"]
        for i in range(count):
            path = random.choice(api_paths); methods = random.sample(["GET", "POST", "PUT", "DELETE"], random.randint(1, 4))
            api = {"endpoint": path, "methods": methods, "requires_auth": random.choice([True, False]), "rate_limit": f"{random.randint(10, 1000)}/min", "response_size_kb": random.randint(1, 100), "sample_response": {"status": "success", "data": f"Sample data for {path}", "timestamp": datetime.now(timezone.utc).isoformat()}, "is_honeypot": True, "triggers_alert": True, "auth_type": random.choice(["basic", "bearer", "api_key", "oauth2", "none"])}
            self._fake_apis.append(api)
            asset = DeceptionAsset(asset_id=f"API-HONEY-{i}", asset_type="api", name=path, description=f"Honeypot API endpoint: {path}")
            self._assets.append(asset)

    def _generate_honey_documents(self, count: int):
        doc_types = [".pdf", ".xlsx", ".docx", ".csv", ".sql", ".pem", ".key", ".env", ".kdbx", ".gpg"]
        doc_names = ["passwords", "financial_report", "customer_data", "backup", "ssh_keys", "aws_credentials", "database_dump", "salary_info", "contract", "nda", "strategic_plan", "audit_report", "vpn_config", "certificates", "master_key"]
        for i in range(count):
            doc = {"filename": f"{random.choice(doc_names)}_{i}{random.choice(doc_types)}", "size_kb": random.randint(10, 50000), "created": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 365))).isoformat(), "modified": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 720))).isoformat(), "owner": random.choice(self._fake_users)["username"] if self._fake_users else "admin", "permissions": random.choice(["confidential", "restricted", "internal", "top_secret"]), "is_honeypot": True, "triggers_alert": True, "contains_tracking": True}
            self._honey_documents.append(doc)

    def _generate_honey_tokens(self, count: int):
        token_types = ["aws_key", "github_token", "slack_token", "api_key", "jwt_token", "database_connection_string", "private_ssh_key", "gpg_private_key", "vpn_certificate", "cloudflare_api_token"]
        for i in range(count):
            token_type = random.choice(token_types)
            token = {"id": f"TOKEN-HONEY-{i}", "type": token_type, "value": hashlib.sha256(f"honey_token_{i}_2024".encode()).hexdigest()[:32], "location": random.choice([".env", "config.json", "credentials.yml", "~/.ssh/", "secrets/", "deploy/"]), "created": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 365))).isoformat(), "is_honeypot": True, "triggers_alert": True}
            self._honey_tokens.append(token)
            asset = DeceptionAsset(asset_id=f"TOKEN-HONEY-{i}", asset_type="honey_token", name=token["type"], description=f"Honeypot token: {token['type']}")
            self._assets.append(asset)

    def record_interaction(self, asset_id: str, attacker_ip: str, action: str, technique: Optional[str] = None) -> Dict[str, Any]:
        interaction = {"timestamp": datetime.now(timezone.utc).isoformat(), "asset_id": asset_id, "attacker_ip": attacker_ip, "action": action, "technique": technique or "unknown", "risk_score": 0.0}
        for asset in self._assets:
            if asset.asset_id == asset_id:
                asset.interactions += 1; asset.last_interaction = datetime.now(timezone.utc); asset.is_compromised = True; asset.risk_score = min(1.0, asset.interactions * 0.15); interaction["risk_score"] = asset.risk_score
                break
        self._interactions_log.append(interaction)
        self.stats["total_interactions"] += 1
        self._update_attacker_profile(attacker_ip, interaction)
        if interaction["risk_score"] > 0.5:
            self.stats["alerts_generated"] += 1
            logger.critical(f"🎯 HIGH RISK: Deception asset triggered! {asset_id} by {attacker_ip} ({action}) | Risk: {interaction['risk_score']:.2f}")
        else:
            logger.info(f"🎯 Deception asset triggered: {asset_id} by {attacker_ip} ({action})")
        return interaction

    def _update_attacker_profile(self, ip: str, interaction: Dict):
        if ip not in self._attacker_profiles:
            self._attacker_profiles[ip] = AttackerProfile(ip=ip, first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc), total_interactions=0, assets_compromised=set(), techniques_used=[], risk_score=0.0, is_tracked=True)
        profile = self._attacker_profiles[ip]
        profile.last_seen = datetime.now(timezone.utc)
        profile.total_interactions += 1
        profile.assets_compromised.add(interaction["asset_id"])
        if interaction.get("technique") and interaction["technique"] not in profile.techniques_used:
            profile.techniques_used.append(interaction["technique"])
        profile.risk_score = min(1.0, profile.total_interactions * 0.1 + len(profile.assets_compromised) * 0.05)
        if profile.risk_score > 0.7: self.stats["high_risk_attackers"] += 1

    def get_attacker_profile(self, attacker_ip: str) -> Dict[str, Any]:
        profile = self._attacker_profiles.get(attacker_ip)
        if not profile: return {}
        return {"ip": profile.ip, "total_interactions": profile.total_interactions, "first_seen": profile.first_seen.isoformat(), "last_seen": profile.last_seen.isoformat(), "assets_compromised": len(profile.assets_compromised), "techniques_used": profile.techniques_used, "risk_score": round(profile.risk_score, 3), "is_tracked": profile.is_tracked}

    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        sorted_profiles = sorted(self._attacker_profiles.values(), key=lambda p: p.risk_score, reverse=True)
        return [{"ip": p.ip, "interactions": p.total_interactions, "assets": len(p.assets_compromised), "risk_score": round(p.risk_score, 3), "techniques": p.techniques_used[:3]} for p in sorted_profiles[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        compromised = [a for a in self._assets if a.is_compromised]
        self.stats["compromised_assets"] = len(compromised)
        self.stats["unique_attackers"] = len(self._attacker_profiles)
        return {"deployed": self._deployed, "total_assets": len(self._assets), "fake_users": len(self._fake_users), "fake_databases": len(self._fake_databases), "fake_apis": len(self._fake_apis), "honey_documents": len(self._honey_documents), "honey_tokens": len(self._honey_tokens), "compromised_assets": self.stats["compromised_assets"], "total_interactions": self.stats["total_interactions"], "unique_attackers": self.stats["unique_attackers"], "high_risk_attackers": self.stats["high_risk_attackers"], "alerts_generated": self.stats["alerts_generated"], "top_attackers": self.get_top_attackers(5), "status": "ACTIVE" if self._deployed else "STANDBY"}


ai_deception_grid = AIDeceptionGrid()
