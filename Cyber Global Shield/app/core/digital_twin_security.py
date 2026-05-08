"""
Cyber Global Shield — Digital Twin Security
Jumeau numérique de l'infrastructure de sécurité.
Simulation, prédiction, et validation des configurations de sécurité.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SecurityTwin:
    """A digital twin of a security component."""
    twin_id: str
    component_type: str
    name: str
    config: Dict[str, Any]
    state: Dict[str, Any]
    metrics: Dict[str, float]
    last_sync: datetime
    health_score: float


class DigitalTwinSecurity:
    """
    Jumeau numérique de sécurité.
    
    Capacités:
    - Réplication en temps réel de l'infrastructure
    - Simulation de scénarios d'attaque
    - Prédiction de l'impact des changements
    - Validation des configurations
    - Détection de drift
    - What-if analysis
    """

    def __init__(self):
        self._twins: Dict[str, SecurityTwin] = {}
        self._simulations: List[Dict] = []
        self._drift_log: List[Dict] = []

    def create_twin(self, component_type: str, name: str, config: Dict) -> SecurityTwin:
        """Create a digital twin of a security component."""
        twin_id = f"TWIN-{component_type.upper()}-{len(self._twins)+1}"
        
        twin = SecurityTwin(
            twin_id=twin_id,
            component_type=component_type,
            name=name,
            config=config,
            state=self._initialize_state(component_type),
            metrics=self._initialize_metrics(component_type),
            last_sync=datetime.utcnow(),
            health_score=1.0,
        )
        
        self._twins[twin_id] = twin
        logger.info(f"🔄 Digital twin created: {name} ({twin_id})")
        return twin

    def _initialize_state(self, component_type: str) -> Dict:
        """Initialize twin state based on component type."""
        states = {
            "firewall": {
                "active_rules": 0,
                "connections": 0,
                "blocked_ips": [],
                "throughput": 0,
                "status": "active",
            },
            "ids": {
                "alerts_generated": 0,
                "false_positives": 0,
                "signatures_loaded": 0,
                "status": "monitoring",
            },
            "endpoint": {
                "agents_deployed": 0,
                "active_threats": 0,
                "last_scan": None,
                "status": "protected",
            },
            "siem": {
                "logs_processed": 0,
                "alerts_correlated": 0,
                "storage_used": 0,
                "status": "ingesting",
            },
            "network": {
                "interfaces": 0,
                "bandwidth_usage": 0,
                "latency": 0,
                "packet_loss": 0,
                "status": "operational",
            },
        }
        return states.get(component_type, {"status": "unknown"})

    def _initialize_metrics(self, component_type: str) -> Dict:
        """Initialize metrics for the twin."""
        return {
            "uptime": 100.0,
            "response_time": 0,
            "error_rate": 0,
            "cpu_usage": 0,
            "memory_usage": 0,
        }

    def simulate_attack(self, twin_id: str, attack_type: str, intensity: float) -> Dict:
        """Simulate an attack on a digital twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}

        simulation = {
            "simulation_id": f"SIM-{len(self._simulations)+1}",
            "twin_id": twin_id,
            "attack_type": attack_type,
            "intensity": intensity,
            "timestamp": datetime.utcnow().isoformat(),
            "impact": self._calculate_impact(twin, attack_type, intensity),
            "defense_success": False,
            "recommendations": [],
        }

        # Simulate defense
        defense_score = twin.health_score * 0.7 + twin.metrics.get("uptime", 50) / 100 * 0.3
        simulation["defense_success"] = defense_score > intensity
        
        # Generate recommendations
        if not simulation["defense_success"]:
            simulation["recommendations"] = self._generate_recommendations(
                twin, attack_type
            )

        self._simulations.append(simulation)
        
        logger.info(
            f"🎯 Attack simulation on {twin.name}: {attack_type} "
            f"(intensity: {intensity:.0%}, defended: {simulation['defense_success']})"
        )

        return simulation

    def _calculate_impact(self, twin: SecurityTwin, attack_type: str, intensity: float) -> Dict:
        """Calculate attack impact on twin."""
        impact = {
            "service_disruption": intensity * 0.6,
            "data_corruption": intensity * 0.3 if attack_type in ["ransomware", "sql_injection"] else 0,
            "performance_degradation": intensity * 0.4,
            "configuration_changes": intensity * 0.2,
        }
        
        # Adjust based on twin health
        for key in impact:
            impact[key] *= (1 - twin.health_score * 0.5)
        
        return impact

    def _generate_recommendations(self, twin: SecurityTwin, attack_type: str) -> List[str]:
        """Generate defense recommendations."""
        recommendations_map = {
            "ddos": [
                "Enable rate limiting",
                "Deploy WAF",
                "Increase bandwidth capacity",
                "Enable DDoS protection service",
            ],
            "ransomware": [
                "Enable file integrity monitoring",
                "Deploy endpoint detection",
                "Implement backup strategy",
                "Block suspicious processes",
            ],
            "sql_injection": [
                "Enable WAF SQL injection rules",
                "Implement parameterized queries",
                "Deploy database firewall",
                "Enable query logging",
            ],
            "brute_force": [
                "Enable account lockout",
                "Implement MFA",
                "Deploy rate limiting",
                "Enable failed login alerts",
            ],
            "phishing": [
                "Deploy email security gateway",
                "Enable DMARC/DKIM/SPF",
                "Conduct security awareness training",
                "Implement URL filtering",
            ],
        }
        
        return recommendations_map.get(attack_type, [
            "Review security controls",
            "Update defense mechanisms",
            "Monitor for similar attacks",
        ])

    def detect_drift(self, twin_id: str, current_config: Dict) -> List[Dict]:
        """Detect configuration drift in a digital twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return []

        drifts = []
        
        for key, expected_value in twin.config.items():
            current_value = current_config.get(key)
            if current_value != expected_value:
                drift = {
                    "twin_id": twin_id,
                    "component": twin.name,
                    "parameter": key,
                    "expected": expected_value,
                    "actual": current_value,
                    "severity": "high" if key in ["security_policy", "encryption", "access_control"] else "medium",
                    "detected_at": datetime.utcnow().isoformat(),
                }
                drifts.append(drift)
                self._drift_log.append(drift)

        if drifts:
            logger.warning(
                f"⚠️ Configuration drift detected in {twin.name}: "
                f"{len(drifts)} changes found"
            )

        return drifts

    def what_if_analysis(self, twin_id: str, changes: Dict) -> Dict:
        """Perform what-if analysis for configuration changes."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}

        analysis = {
            "twin_id": twin_id,
            "component": twin.name,
            "proposed_changes": changes,
            "risk_assessment": self._assess_change_risk(twin, changes),
            "predicted_impact": self._predict_change_impact(twin, changes),
            "recommendation": "",
        }

        # Generate recommendation
        risk = analysis["risk_assessment"]["overall_risk"]
        if risk < 0.3:
            analysis["recommendation"] = "Safe to apply"
        elif risk < 0.6:
            analysis["recommendation"] = "Apply with caution, monitor closely"
        else:
            analysis["recommendation"] = "Do not apply - high risk"

        return analysis

    def _assess_change_risk(self, twin: SecurityTwin, changes: Dict) -> Dict:
        """Assess risk of proposed changes."""
        risk_score = 0.0
        risk_factors = []
        
        for key, value in changes.items():
            if key in ["security_policy", "firewall_rules", "access_control"]:
                risk_score += 0.3
                risk_factors.append(f"Critical component change: {key}")
            elif key in ["logging", "monitoring", "alerts"]:
                risk_score += 0.1
                risk_factors.append(f"Monitoring change: {key}")
            else:
                risk_score += 0.05
                risk_factors.append(f"Standard change: {key}")

        return {
            "overall_risk": min(1.0, risk_score),
            "risk_factors": risk_factors,
            "change_complexity": "high" if risk_score > 0.5 else "medium",
        }

    def _predict_change_impact(self, twin: SecurityTwin, changes: Dict) -> Dict:
        """Predict impact of changes on twin."""
        return {
            "availability_impact": 0.1 if any(k in changes for k in ["firewall_rules", "network_config"]) else 0.05,
            "security_impact": -0.2 if any("security" in k for k in changes) else 0,
            "performance_impact": 0.1 if any(k in changes for k in ["logging", "monitoring"]) else 0.05,
            "estimated_downtime_seconds": 30 if "firewall_rules" in changes else 5,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get digital twin statistics."""
        return {
            "total_twins": len(self._twins),
            "by_type": dict(
                (t.component_type, len([tw for tw in self._twins.values() if tw.component_type == t.component_type]))
                for t in self._twins.values()
            ),
            "total_simulations": len(self._simulations),
            "avg_health_score": (
                sum(t.health_score for t in self._twins.values()) / len(self._twins)
                if self._twins else 0
            ),
            "drifts_detected": len(self._drift_log),
            "status": "SYNCHRONIZED",
        }


digital_twin_security = DigitalTwinSecurity()
