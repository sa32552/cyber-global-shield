"""
Cyber Global Shield — Automated Threat Modeling
Modélisation automatique des menaces basée sur l'architecture système.
Génère des diagrammes de menace, identifie les vecteurs d'attaque, et priorise les risques.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ThreatModel:
    """A complete threat model for a system."""
    model_id: str
    system_name: str
    created_at: datetime
    assets: List[Dict]
    threats: List[Dict]
    attack_vectors: List[Dict]
    mitigations: List[Dict]
    risk_score: float
    stride_coverage: Dict[str, bool]


@dataclass
class AttackVector:
    """An identified attack vector."""
    vector_id: str
    name: str
    description: str
    source: str
    target: str
    likelihood: float  # 0-1
    impact: float  # 0-1
    risk_score: float
    mitre_techniques: List[str]


class AutomatedThreatModeling:
    """
    Modélisation automatique des menaces.
    
    Basé sur:
    - STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
    - DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
    - MITRE ATT&CK
    - OWASP Top 10
    - Architecture system analysis
    """

    def __init__(self):
        self._models: List[ThreatModel] = []
        self._threat_library = self._load_threat_library()
        self._mitre_mapping = self._load_mitre_mapping()

    def _load_threat_library(self) -> Dict[str, List[Dict]]:
        """Load threat patterns library."""
        return {
            "web_application": [
                {"name": "SQL Injection", "stride": "Tampering", "owasp": "A03:2021"},
                {"name": "XSS", "stride": "Spoofing", "owasp": "A07:2021"},
                {"name": "Broken Authentication", "stride": "Spoofing", "owasp": "A01:2021"},
                {"name": "Sensitive Data Exposure", "stride": "Info Disclosure", "owasp": "A02:2021"},
                {"name": "SSRF", "stride": "Spoofing", "owasp": "A10:2021"},
            ],
            "api": [
                {"name": "Mass Assignment", "stride": "Tampering", "owasp": "API1:2023"},
                {"name": "Broken Object Level Auth", "stride": "Elevation", "owasp": "API1:2023"},
                {"name": "Rate Limiting Bypass", "stride": "DoS", "owasp": "API4:2023"},
            ],
            "cloud_infrastructure": [
                {"name": "IAM Misconfiguration", "stride": "Elevation", "mitre": "T1078"},
                {"name": "S3 Bucket Exposure", "stride": "Info Disclosure", "mitre": "T1530"},
                {"name": "Container Escape", "stride": "Elevation", "mitre": "T1611"},
            ],
            "network": [
                {"name": "Man-in-the-Middle", "stride": "Spoofing", "mitre": "T1557"},
                {"name": "DNS Spoofing", "stride": "Spoofing", "mitre": "T1558"},
                {"name": "Port Scanning", "stride": "Info Disclosure", "mitre": "T1046"},
            ],
            "identity": [
                {"name": "Credential Stuffing", "stride": "Spoofing", "mitre": "T1110"},
                {"name": "Privilege Escalation", "stride": "Elevation", "mitre": "T1068"},
                {"name": "Token Theft", "stride": "Spoofing", "mitre": "T1528"},
            ],
        }

    def _load_mitre_mapping(self) -> Dict[str, str]:
        """Load MITRE ATT&CK technique mapping."""
        return {
            "SQL Injection": "T1190",
            "XSS": "T1059.007",
            "Broken Authentication": "T1078",
            "SSRF": "T1190",
            "Credential Stuffing": "T1110",
            "Privilege Escalation": "T1068",
            "Container Escape": "T1611",
            "S3 Bucket Exposure": "T1530",
            "DNS Spoofing": "T1558",
            "Man-in-the-Middle": "T1557",
        }

    def analyze_architecture(self, system_name: str, components: List[Dict]) -> ThreatModel:
        """Analyze system architecture and generate threat model."""
        model_id = f"TM-{int(datetime.utcnow().timestamp())}"
        
        # Step 1: Identify assets
        assets = self._identify_assets(components)
        
        # Step 2: Identify threats per component
        threats = []
        for component in components:
            component_threats = self._identify_threats(component)
            threats.extend(component_threats)
        
        # Step 3: Map attack vectors
        attack_vectors = self._map_attack_vectors(components, threats)
        
        # Step 4: Generate mitigations
        mitigations = self._generate_mitigations(threats, attack_vectors)
        
        # Step 5: Calculate risk score
        risk_score = self._calculate_risk_score(threats, attack_vectors)
        
        # Step 6: STRIDE coverage
        stride_coverage = self._check_stride_coverage(threats)

        model = ThreatModel(
            model_id=model_id,
            system_name=system_name,
            created_at=datetime.utcnow(),
            assets=assets,
            threats=threats,
            attack_vectors=attack_vectors,
            mitigations=mitigations,
            risk_score=risk_score,
            stride_coverage=stride_coverage,
        )

        self._models.append(model)
        
        logger.info(
            f"📋 Threat model generated: {system_name} "
            f"(risk: {risk_score:.1%}, threats: {len(threats)}, "
            f"vectors: {len(attack_vectors)})"
        )

        return model

    def _identify_assets(self, components: List[Dict]) -> List[Dict]:
        """Identify assets from system components."""
        assets = []
        for component in components:
            asset = {
                "name": component.get("name", "unknown"),
                "type": component.get("type", "service"),
                "criticality": self._assess_criticality(component),
                "data_classification": component.get("data_classification", "internal"),
                "exposure": component.get("exposure", "internal"),
            }
            assets.append(asset)
        return assets

    def _assess_criticality(self, component: Dict) -> str:
        """Assess component criticality."""
        critical_types = ["database", "auth_service", "payment_gateway", "certificate_authority"]
        high_types = ["api_gateway", "web_server", "file_storage", "message_queue"]
        
        comp_type = component.get("type", "")
        if comp_type in critical_types:
            return "critical"
        elif comp_type in high_types:
            return "high"
        return "medium"

    def _identify_threats(self, component: Dict) -> List[Dict]:
        """Identify threats for a component."""
        threats = []
        comp_type = component.get("type", "")
        comp_name = component.get("name", "unknown")
        
        # Match component type to threat library
        for category, category_threats in self._threat_library.items():
            if category in comp_type or comp_type in category:
                for threat_template in category_threats:
                    threat = threat_template.copy()
                    threat["target"] = comp_name
                    threat["threat_id"] = f"THREAT-{len(threats)+1}"
                    threat["likelihood"] = self._estimate_likelihood(component, threat)
                    threat["impact"] = self._estimate_impact(component, threat)
                    threat["risk"] = threat["likelihood"] * threat["impact"]
                    threats.append(threat)
        
        return threats

    def _estimate_likelihood(self, component: Dict, threat: Dict) -> float:
        """Estimate threat likelihood."""
        likelihood = 0.5  # Default
        
        # External exposure increases likelihood
        if component.get("exposure") == "public":
            likelihood += 0.3
        elif component.get("exposure") == "internal":
            likelihood += 0.1
        
        # Known vulnerabilities increase likelihood
        if component.get("known_vulnerabilities"):
            likelihood += 0.2
        
        return min(likelihood, 1.0)

    def _estimate_impact(self, component: Dict, threat: Dict) -> float:
        """Estimate threat impact."""
        impact = 0.5  # Default
        
        # Critical assets have higher impact
        criticality = self._assess_criticality(component)
        if criticality == "critical":
            impact += 0.3
        elif criticality == "high":
            impact += 0.2
        
        # Data classification
        data_class = component.get("data_classification", "")
        if data_class in ["pii", "financial", "healthcare"]:
            impact += 0.2
        
        return min(impact, 1.0)

    def _map_attack_vectors(self, components: List[Dict], threats: List[Dict]) -> List[Dict]:
        """Map attack vectors between components."""
        vectors = []
        
        for i, source in enumerate(components):
            for j, target in enumerate(components):
                if i != j:
                    # Check if there's a communication path
                    if self._has_communication_path(source, target):
                        vector = {
                            "vector_id": f"VEC-{len(vectors)+1}",
                            "source": source.get("name"),
                            "target": target.get("name"),
                            "protocol": source.get("protocol", "unknown"),
                            "risk_score": self._calculate_vector_risk(source, target, threats),
                            "mitre_techniques": self._get_vector_mitre(source, target),
                        }
                        vectors.append(vector)
        
        return vectors

    def _has_communication_path(self, source: Dict, target: Dict) -> bool:
        """Check if two components communicate."""
        # Simplified: check if source connects to target
        connections = source.get("connects_to", [])
        return target.get("name") in connections

    def _calculate_vector_risk(self, source: Dict, target: Dict, threats: List[Dict]) -> float:
        """Calculate risk score for an attack vector."""
        risk = 0.0
        
        # Source exposure
        if source.get("exposure") == "public":
            risk += 0.3
        
        # Target criticality
        criticality = self._assess_criticality(target)
        if criticality == "critical":
            risk += 0.3
        elif criticality == "high":
            risk += 0.2
        
        # Relevant threats
        target_name = target.get("name")
        relevant = [t for t in threats if t.get("target") == target_name]
        risk += len(relevant) * 0.05
        
        return min(risk, 1.0)

    def _get_vector_mitre(self, source: Dict, target: Dict) -> List[str]:
        """Get MITRE techniques for attack vector."""
        techniques = []
        
        if source.get("exposure") == "public":
            techniques.append("T1190")  # Exploit Public-Facing Application
        
        target_type = target.get("type", "")
        if target_type == "database":
            techniques.append("T1213")  # Data from Information Repositories
        elif target_type == "auth_service":
            techniques.append("T1078")  # Valid Accounts
        
        return techniques

    def _generate_mitigations(self, threats: List[Dict], vectors: List[Dict]) -> List[Dict]:
        """Generate mitigations for identified threats."""
        mitigations = []
        
        for threat in threats:
            mitigation = {
                "threat_id": threat.get("threat_id"),
                "threat_name": threat.get("name"),
                "recommended_controls": self._get_controls(threat),
                "priority": "high" if threat.get("risk", 0) > 0.7 else "medium",
                "implementation_effort": self._estimate_effort(threat),
            }
            mitigations.append(mitigation)
        
        return mitigations

    def _get_controls(self, threat: Dict) -> List[str]:
        """Get recommended security controls."""
        controls_map = {
            "SQL Injection": ["WAF", "Parameterized Queries", "Input Validation"],
            "XSS": ["CSP Headers", "Output Encoding", "XSS Filter"],
            "Broken Authentication": ["MFA", "Rate Limiting", "Session Management"],
            "SSRF": ["Network Segmentation", "Allow List", "Input Validation"],
            "Credential Stuffing": ["MFA", "CAPTCHA", "Account Lockout"],
            "Privilege Escalation": ["Least Privilege", "PAM", "RBAC"],
            "S3 Bucket Exposure": ["Bucket Policies", "Access Logs", "Encryption"],
            "Container Escape": ["Seccomp", "AppArmor", "Read-Only Root FS"],
        }
        
        return controls_map.get(threat.get("name", ""), ["Security Review", "Monitoring"])

    def _estimate_effort(self, threat: Dict) -> str:
        """Estimate implementation effort."""
        risk = threat.get("risk", 0)
        if risk > 0.7:
            return "immediate"
        elif risk > 0.4:
            return "short_term"
        return "long_term"

    def _calculate_risk_score(self, threats: List[Dict], vectors: List[Dict]) -> float:
        """Calculate overall risk score."""
        if not threats:
            return 0.0
        
        avg_threat_risk = sum(t.get("risk", 0) for t in threats) / len(threats)
        avg_vector_risk = sum(v.get("risk_score", 0) for v in vectors) / len(vectors) if vectors else 0
        
        return (avg_threat_risk * 0.6 + avg_vector_risk * 0.4)

    def _check_stride_coverage(self, threats: List[Dict]) -> Dict[str, bool]:
        """Check STRIDE coverage."""
        stride = {
            "Spoofing": False,
            "Tampering": False,
            "Repudiation": False,
            "Info Disclosure": False,
            "DoS": False,
            "Elevation": False,
        }
        
        for threat in threats:
            stride_type = threat.get("stride", "")
            if stride_type in stride:
                stride[stride_type] = True
        
        return stride

    def get_stats(self) -> Dict[str, Any]:
        """Get threat modeling statistics."""
        return {
            "total_models": len(self._models),
            "total_threats": sum(len(m.threats) for m in self._models),
            "total_vectors": sum(len(m.attack_vectors) for m in self._models),
            "avg_risk_score": (
                sum(m.risk_score for m in self._models) / len(self._models)
                if self._models else 0
            ),
            "stride_coverage": (
                {k: any(m.stride_coverage[k] for m in self._models)
                 for k in ["Spoofing", "Tampering", "Repudiation", 
                          "Info Disclosure", "DoS", "Elevation"]}
                if self._models else {}
            ),
            "status": "MODELING",
        }


automated_threat_modeling = AutomatedThreatModeling()
