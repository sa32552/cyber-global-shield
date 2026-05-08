"""
Cyber Global Shield — Predictive Cyber Insurance
Assurance cyber prédictive basée sur l'analyse de risque en temps réel.
Calcule les primes, détecte les changements de risque, et prévient les sinistres.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CyberRiskProfile:
    """A cyber risk profile for insurance."""
    organization: str
    industry: str
    revenue: float
    employees: int
    data_sensitivity: str
    security_maturity: float  # 0-1
    incident_history: List[Dict]
    risk_score: float
    premium_estimate: float
    coverage_limit: float


class PredictiveCyberInsurance:
    """
    Assurance cyber prédictive.
    
    Calcule:
    - Score de risque cyber en temps réel
    - Prime d'assurance dynamique
    - Couverture recommandée
    - Prévention des sinistres
    - ROI des mesures de sécurité
    """

    def __init__(self):
        self._profiles: Dict[str, CyberRiskProfile] = {}
        self._industry_risk = self._load_industry_risk()
        self._incident_costs = self._load_incident_costs()

    def _load_industry_risk(self) -> Dict[str, float]:
        """Load industry risk multipliers."""
        return {
            "healthcare": 1.8,
            "finance": 1.6,
            "technology": 1.4,
            "government": 1.3,
            "retail": 1.2,
            "manufacturing": 1.1,
            "education": 1.0,
            "nonprofit": 0.8,
            "small_business": 0.7,
        }

    def _load_incident_costs(self) -> Dict[str, float]:
        """Load average incident costs by type."""
        return {
            "ransomware": 1500000,
            "data_breach": 4000000,
            "business_email": 500000,
            "ddos": 300000,
            "insider_threat": 600000,
            "supply_chain": 2000000,
            "social_engineering": 250000,
        }

    def assess_risk(self, organization: str, data: Dict) -> CyberRiskProfile:
        """Assess cyber risk for an organization."""
        # Base risk score
        base_risk = 0.5
        
        # Industry factor
        industry = data.get("industry", "technology")
        industry_mult = self._industry_risk.get(industry, 1.0)
        
        # Size factor
        revenue = data.get("revenue", 1000000)
        employees = data.get("employees", 100)
        size_factor = min(1.5, max(0.5, (revenue / 10000000) * 0.5 + (employees / 1000) * 0.5))
        
        # Data sensitivity
        sensitivity = data.get("data_sensitivity", "low")
        sensitivity_mult = {"low": 0.8, "medium": 1.0, "high": 1.3, "critical": 1.6}.get(sensitivity, 1.0)
        
        # Security maturity
        maturity = data.get("security_maturity", 0.5)
        maturity_factor = 1.0 - (maturity * 0.5)  # Better security = lower risk
        
        # Incident history
        incidents = data.get("incident_history", [])
        incident_factor = 1.0 + (len(incidents) * 0.1)
        
        # Calculate final risk score
        risk_score = base_risk * industry_mult * size_factor * sensitivity_mult * maturity_factor * incident_factor
        risk_score = min(1.0, max(0.0, risk_score))
        
        # Calculate premium
        base_premium = revenue * 0.002  # 0.2% of revenue base
        premium = base_premium * (1 + risk_score * 2)  # Risk-adjusted
        
        # Calculate coverage
        coverage = revenue * 0.1  # 10% of revenue recommended
        
        profile = CyberRiskProfile(
            organization=organization,
            industry=industry,
            revenue=revenue,
            employees=employees,
            data_sensitivity=sensitivity,
            security_maturity=maturity,
            incident_history=incidents,
            risk_score=risk_score,
            premium_estimate=premium,
            coverage_limit=coverage,
        )
        
        self._profiles[organization] = profile
        
        logger.info(
            f"📊 Risk assessment for {organization}: "
            f"risk={risk_score:.1%}, premium=${premium:,.0f}, "
            f"coverage=${coverage:,.0f}"
        )
        
        return profile

    def calculate_roi(self, organization: str, security_investment: float) -> Dict[str, Any]:
        """Calculate ROI of security investments."""
        profile = self._profiles.get(organization)
        if not profile:
            return {"error": "No risk profile found"}
        
        # Calculate risk reduction
        risk_reduction = min(0.5, security_investment / (profile.revenue * 0.01))
        new_risk = profile.risk_score * (1 - risk_reduction)
        
        # Premium reduction
        premium_reduction = profile.premium_estimate * risk_reduction
        
        # Expected loss reduction
        expected_loss = profile.risk_score * 2000000  # Average potential loss
        loss_reduction = expected_loss * risk_reduction
        
        # ROI calculation
        total_benefit = premium_reduction + loss_reduction
        roi = ((total_benefit - security_investment) / security_investment) * 100 if security_investment > 0 else 0
        
        return {
            "organization": organization,
            "security_investment": security_investment,
            "risk_reduction": risk_reduction * 100,
            "new_risk_score": new_risk,
            "premium_reduction": premium_reduction,
            "expected_loss_reduction": loss_reduction,
            "total_benefit": total_benefit,
            "roi_percentage": roi,
            "payback_period_months": (security_investment / (total_benefit / 12)) if total_benefit > 0 else float('inf'),
            "recommendation": "Invest" if roi > 0 else "Reconsider",
        }

    def predict_incident_probability(self, organization: str) -> Dict[str, float]:
        """Predict probability of different incident types."""
        profile = self._profiles.get(organization)
        if not profile:
            return {}
        
        base_prob = profile.risk_score * 0.3
        
        return {
            "ransomware": base_prob * 1.5,
            "data_breach": base_prob * 1.3,
            "phishing": base_prob * 1.8,
            "insider_threat": base_prob * 0.8,
            "ddos": base_prob * 0.6,
            "supply_chain": base_prob * 0.4,
            "any_incident_12_months": min(1.0, base_prob * 5),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get insurance statistics."""
        return {
            "total_assessments": len(self._profiles),
            "avg_risk_score": (
                sum(p.risk_score for p in self._profiles.values()) / len(self._profiles)
                if self._profiles else 0
            ),
            "total_premium": sum(p.premium_estimate for p in self._profiles.values()),
            "total_coverage": sum(p.coverage_limit for p in self._profiles.values()),
            "industries": list(set(p.industry for p in self._profiles.values())),
            "status": "UNDERWRITING",
        }


predictive_insurance = PredictiveCyberInsurance()
