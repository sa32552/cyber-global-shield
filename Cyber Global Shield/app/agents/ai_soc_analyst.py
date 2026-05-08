"""
Cyber Global Shield — AI-Powered SOC Analyst
Agent IA qui analyse les alertes de sécurité comme un analyste SOC humain.
Tri, investigation, recommandation, et escalade autonome.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalystDecision(str, Enum):
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    NEEDS_INVESTIGATION = "needs_investigation"
    ESCALATED = "escalated"


@dataclass
class AlertAnalysis:
    """Analysis result from the AI SOC analyst."""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    decision: AnalystDecision
    confidence: float
    reasoning: str
    recommended_actions: List[str]
    mitre_techniques: List[str]
    related_alerts: List[str]
    investigation_depth: str  # surface, deep, full


class AISOCAnalyst:
    """
    AI SOC Analyst — Analyse les alertes comme un humain.
    
    Capacités:
    - Tri intelligent des alertes (triage)
    - Corrélation cross-sources
    - Enrichissement contextuel
    - Décision False Positive vs True Positive
    - Recommandations d'action
    - Escalade automatique
    - Investigation autonome
    """

    def __init__(self):
        self._analyses: List[AlertAnalysis] = []
        self._knowledge_base: Dict[str, Any] = self._load_knowledge_base()
        self._false_positive_patterns: List[str] = self._load_fp_patterns()
        self._analysis_queue: List[Dict] = []

    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Load threat intelligence knowledge base."""
        return {
            "known_iocs": {
                "ip": ["185.220.101.x", "91.121.87.x", "5.255.88.x"],
                "domain": ["emotet.xyz", "trickbot.net", "cobaltstrike.io"],
                "hash": ["e3b0c44298fc1c149afbf4c8996fb924"],
            },
            "attack_patterns": {
                "ransomware": ["encryption", "file_rename", "ransom_note"],
                "phishing": ["suspicious_link", "credential_harvesting"],
                "lateral_movement": ["pass_the_hash", "wmi_exec", "ps_remoting"],
            },
            "false_positive_indicators": [
                "known_good_software",
                "admin_activity",
                "scheduled_scan",
                "update_service",
            ],
        }

    def _load_fp_patterns(self) -> List[str]:
        """Load known false positive patterns."""
        return [
            "windows_update",
            "antivirus_scan",
            "backup_software",
            "monitoring_agent",
            "vpn_reconnect",
            "dns_resolution_failure",
            "ssl_cert_expiry",
            "rate_limiting",
        ]

    def analyze_alert(self, alert: Dict[str, Any]) -> AlertAnalysis:
        """Analyze a security alert like a human SOC analyst."""
        alert_id = alert.get("id", f"ALERT-{len(self._analyses)+1}")
        
        # Step 1: Initial triage
        severity = self._triage(alert)
        
        # Step 2: Context enrichment
        enriched = self._enrich_context(alert)
        
        # Step 3: False positive check
        is_fp = self._check_false_positive(alert)
        
        # Step 4: Correlation with other alerts
        related = self._correlate_alerts(alert)
        
        # Step 5: MITRE ATT&CK mapping
        mitre_techniques = self._map_mitre(alert)
        
        # Step 6: Decision making
        if is_fp:
            decision = AnalystDecision.FALSE_POSITIVE
            confidence = 0.85
            reasoning = "Matches known false positive pattern"
            actions = ["Log and dismiss"]
            depth = "surface"
        elif severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            decision = AnalystDecision.TRUE_POSITIVE
            confidence = 0.75
            reasoning = f"High severity alert with {len(mitre_techniques)} MITRE techniques"
            actions = self._generate_recommendations(alert, severity)
            depth = "full"
        else:
            decision = AnalystDecision.NEEDS_INVESTIGATION
            confidence = 0.5
            reasoning = "Medium/Low severity, requires further investigation"
            actions = ["Queue for analyst review"]
            depth = "deep"

        analysis = AlertAnalysis(
            alert_id=alert_id,
            timestamp=datetime.utcnow(),
            severity=severity,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            recommended_actions=actions,
            mitre_techniques=mitre_techniques,
            related_alerts=related,
            investigation_depth=depth,
        )

        self._analyses.append(analysis)
        
        if decision == AnalystDecision.TRUE_POSITIVE:
            logger.critical(
                f"🚨 AI SOC Analyst: TRUE POSITIVE - {alert_id} "
                f"(severity: {severity.value}, confidence: {confidence:.0%})"
            )
        elif decision == AnalystDecision.FALSE_POSITIVE:
            logger.info(
                f"✅ AI SOC Analyst: FALSE POSITIVE - {alert_id} "
                f"(confidence: {confidence:.0%})"
            )

        return analysis

    def _triage(self, alert: Dict) -> AlertSeverity:
        """Initial triage of alert severity."""
        score = 0
        
        # Source reputation
        source = alert.get("source", "")
        if source in ["firewall", "edr", "ids"]:
            score += 3
        elif source in ["antivirus", "email"]:
            score += 2
        else:
            score += 1

        # Alert type
        alert_type = alert.get("type", "")
        critical_types = ["ransomware", "c2", "data_exfil", "lateral_movement"]
        high_types = ["malware", "phishing", "brute_force", "privilege_escalation"]
        
        if alert_type in critical_types:
            score += 5
        elif alert_type in high_types:
            score += 3
        else:
            score += 1

        # Affected assets
        assets = alert.get("affected_assets", [])
        if len(assets) > 10:
            score += 3
        elif len(assets) > 3:
            score += 2

        # Map score to severity
        if score >= 8:
            return AlertSeverity.CRITICAL
        elif score >= 5:
            return AlertSeverity.HIGH
        elif score >= 3:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def _enrich_context(self, alert: Dict) -> Dict:
        """Enrich alert with contextual information."""
        enriched = alert.copy()
        
        # Add asset criticality
        asset = alert.get("asset", "")
        enriched["asset_criticality"] = self._get_asset_criticality(asset)
        
        # Add user risk score
        user = alert.get("user", "")
        enriched["user_risk_score"] = self._get_user_risk(user)
        
        # Add time context
        hour = datetime.utcnow().hour
        enriched["is_off_hours"] = hour < 6 or hour > 22
        
        return enriched

    def _get_asset_criticality(self, asset: str) -> str:
        """Determine asset criticality."""
        critical_assets = ["domain_controller", "database_server", "firewall", "certificate_authority"]
        high_assets = ["file_server", "mail_server", "web_server", "app_server"]
        
        if asset in critical_assets:
            return "critical"
        elif asset in high_assets:
            return "high"
        return "medium"

    def _get_user_risk(self, user: str) -> float:
        """Get user risk score based on history."""
        # Simulated risk scoring
        return 0.3  # Default medium risk

    def _check_false_positive(self, alert: Dict) -> bool:
        """Check if alert matches known false positive patterns."""
        description = alert.get("description", "").lower()
        source = alert.get("source", "").lower()
        
        for pattern in self._false_positive_patterns:
            if pattern in description or pattern in source:
                return True
        
        return False

    def _correlate_alerts(self, alert: Dict) -> List[str]:
        """Correlate with other recent alerts."""
        related = []
        source_ip = alert.get("source_ip", "")
        target = alert.get("target", "")
        
        for analysis in self._analyses[-50:]:  # Last 50 analyses
            if analysis.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                related.append(analysis.alert_id)
        
        return related[:5]  # Max 5 related

    def _map_mitre(self, alert: Dict) -> List[str]:
        """Map alert to MITRE ATT&CK techniques."""
        mapping = {
            "ransomware": ["T1486", "T1490"],
            "phishing": ["T1566", "T1598"],
            "c2": ["T1071", "T1573"],
            "lateral_movement": ["T1021", "T1550"],
            "brute_force": ["T1110"],
            "data_exfil": ["T1048", "T1567"],
            "privilege_escalation": ["T1068", "T1055"],
            "persistence": ["T1053", "T1543"],
        }
        
        alert_type = alert.get("type", "")
        return mapping.get(alert_type, ["T1078"])  # Default: valid accounts

    def _generate_recommendations(self, alert: Dict, severity: AlertSeverity) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if severity == AlertSeverity.CRITICAL:
            recommendations.extend([
                "Immediately isolate affected hosts",
                "Block C2 communication at firewall",
                "Initiate incident response playbook",
                "Notify SOC manager",
            ])
        elif severity == AlertSeverity.HIGH:
            recommendations.extend([
                "Quarantine affected endpoint",
                "Reset compromised credentials",
                "Review recent authentication logs",
            ])
        
        # Type-specific recommendations
        alert_type = alert.get("type", "")
        if alert_type == "ransomware":
            recommendations.append("Restore from last clean backup")
        elif alert_type == "phishing":
            recommendations.append("Force password reset for targeted users")
        elif alert_type == "data_exfil":
            recommendations.append("Block outbound data transfer to unknown destinations")
        
        return recommendations

    def get_stats(self) -> Dict[str, Any]:
        """Get AI SOC analyst statistics."""
        recent = [
            a for a in self._analyses
            if (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        return {
            "total_analyzed": len(self._analyses),
            "recent_analyzed": len(recent),
            "true_positives": len([a for a in recent if a.decision == AnalystDecision.TRUE_POSITIVE]),
            "false_positives": len([a for a in recent if a.decision == AnalystDecision.FALSE_POSITIVE]),
            "avg_confidence": (
                sum(a.confidence for a in recent) / len(recent)
                if recent else 0
            ),
            "critical_alerts": len([a for a in recent if a.severity == AlertSeverity.CRITICAL]),
            "status": "ANALYZING",
        }


ai_soc_analyst = AISOCAnalyst()
