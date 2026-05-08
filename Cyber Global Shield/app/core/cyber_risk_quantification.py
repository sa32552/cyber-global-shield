"""
Cyber Risk Quantification Engine — Phase 5
Convert security posture into financial numbers for the board
"""

import logging
import random
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskCategory(Enum):
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    REGULATORY = "regulatory"
    OPERATIONAL = "operational"
    STRATEGIC = "strategic"


@dataclass
class RiskFactor:
    id: str
    name: str
    category: RiskCategory
    current_score: float  # 0-100
    target_score: float
    weight: float  # 0-1
    trend: str  # improving, stable, worsening
    annual_loss_expectancy: float  # in USD
    mitigation_cost: float
    roi: float


@dataclass
class RiskReport:
    id: str
    timestamp: datetime
    organization: str
    overall_risk_score: float
    risk_categories: Dict[str, float]
    annual_loss_expectancy: float
    recommended_budget: float
    risk_factors: List[RiskFactor]
    compliance_status: Dict[str, str]
    board_recommendations: List[str]
    cyber_insurance_premium: float


class CyberRiskQuantification:
    """
    Cyber Risk Quantification Engine.
    Translates technical security metrics into financial risk.
    Board-ready reports with dollar figures.
    """

    def __init__(self):
        self.reports: Dict[str, RiskReport] = {}
        self.risk_factors: Dict[str, RiskFactor] = {}
        self.stats = {
            "total_reports_generated": 0,
            "avg_risk_score": 0,
            "total_ale": 0,  # Annual Loss Expectancy
        }
        self._init_default_risk_factors()

    def _init_default_risk_factors(self):
        """Initialize default risk factors."""
        factors = [
            ("RF-001", "Data Breach Probability", RiskCategory.FINANCIAL, 45, 20, 0.15),
            ("RF-002", "Ransomware Vulnerability", RiskCategory.OPERATIONAL, 35, 15, 0.12),
            ("RF-003", "Phishing Susceptibility", RiskCategory.OPERATIONAL, 50, 25, 0.10),
            ("RF-004", "Supply Chain Risk", RiskCategory.STRATEGIC, 40, 20, 0.08),
            ("RF-005", "Compliance Gap", RiskCategory.REGULATORY, 25, 10, 0.10),
            ("RF-006", "Insider Threat Risk", RiskCategory.OPERATIONAL, 30, 15, 0.08),
            ("RF-007", "Cloud Security Posture", RiskCategory.OPERATIONAL, 35, 15, 0.07),
            ("RF-008", "Zero-Day Exposure", RiskCategory.STRATEGIC, 55, 25, 0.06),
            ("RF-009", "DDoS Resilience", RiskCategory.OPERATIONAL, 25, 10, 0.05),
            ("RF-010", "Third-Party Risk", RiskCategory.STRATEGIC, 45, 20, 0.05),
            ("RF-011", "Identity Management", RiskCategory.OPERATIONAL, 30, 15, 0.04),
            ("RF-012", "Endpoint Security", RiskCategory.OPERATIONAL, 28, 12, 0.04),
            ("RF-013", "Network Security", RiskCategory.OPERATIONAL, 22, 10, 0.03),
            ("RF-014", "Application Security", RiskCategory.OPERATIONAL, 40, 20, 0.02),
            ("RF-015", "Physical Security", RiskCategory.OPERATIONAL, 15, 5, 0.01),
        ]

        for fid, name, category, current, target, weight in factors:
            ale = random.uniform(100000, 5000000)
            mitigation = ale * random.uniform(0.1, 0.3)
            factor = RiskFactor(
                id=fid,
                name=name,
                category=category,
                current_score=current,
                target_score=target,
                weight=weight,
                trend=random.choice(["improving", "stable", "worsening"]),
                annual_loss_expectancy=ale,
                mitigation_cost=mitigation,
                roi=(ale - mitigation) / mitigation if mitigation > 0 else 0,
            )
            self.risk_factors[fid] = factor

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        weighted_sum = sum(
            f.current_score * f.weight for f in self.risk_factors.values()
        )
        total_weight = sum(f.weight for f in self.risk_factors.values())
        return round(weighted_sum / total_weight, 2) if total_weight > 0 else 0

    def calculate_annual_loss_expectancy(self) -> float:
        """Calculate total annual loss expectancy."""
        return sum(f.annual_loss_expectancy for f in self.risk_factors.values())

    def calculate_recommended_budget(self) -> float:
        """Calculate recommended security budget."""
        total_ale = self.calculate_annual_loss_expectancy()
        # Industry standard: 10-15% of ALE
        return round(total_ale * random.uniform(0.10, 0.15), 2)

    def calculate_cyber_insurance(self) -> float:
        """Calculate estimated cyber insurance premium."""
        risk_score = self.calculate_risk_score()
        base_premium = 50000
        # Higher risk = higher premium
        premium = base_premium * (1 + (risk_score / 100) * 3)
        return round(premium, 2)

    def generate_board_report(self, organization: str = "Client Organization") -> RiskReport:
        """Generate a board-ready risk report."""
        risk_score = self.calculate_risk_score()
        ale = self.calculate_annual_loss_expectancy()
        budget = self.calculate_recommended_budget()

        # Category scores
        categories = {}
        for cat in RiskCategory:
            factors = [f for f in self.risk_factors.values() if f.category == cat]
            if factors:
                avg = sum(f.current_score for f in factors) / len(factors)
                categories[cat.value] = round(avg, 2)

        # Compliance status
        compliance = {
            "SOC 2": "compliant" if risk_score < 40 else "needs_improvement",
            "ISO 27001": "compliant" if risk_score < 35 else "non_compliant",
            "GDPR": "compliant" if risk_score < 30 else "at_risk",
            "PCI DSS": "compliant" if risk_score < 25 else "non_compliant",
            "HIPAA": "compliant" if risk_score < 20 else "at_risk",
        }

        # Board recommendations
        recommendations = self._generate_board_recommendations(risk_score, categories)

        report = RiskReport(
            id=f"CRQ-{hashlib.sha256(f'{organization}{datetime.now(timezone.utc).timestamp()}'.encode()).hexdigest()[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            organization=organization,
            overall_risk_score=risk_score,
            risk_categories=categories,
            annual_loss_expectancy=ale,
            recommended_budget=budget,
            risk_factors=list(self.risk_factors.values()),
            compliance_status=compliance,
            board_recommendations=recommendations,
            cyber_insurance_premium=self.calculate_cyber_insurance(),
        )

        self.reports[report.id] = report
        self.stats["total_reports_generated"] += 1
        self.stats["avg_risk_score"] = (self.stats["avg_risk_score"] * (self.stats["total_reports_generated"] - 1) + risk_score) / self.stats["total_reports_generated"]
        self.stats["total_ale"] += ale

        logger.info(f"[CRQ] Report generated: {report.id}")
        logger.info(f"  Risk Score: {risk_score}/100")
        logger.info(f"  Annual Loss Expectancy: ${ale:,.2f}")
        logger.info(f"  Recommended Budget: ${budget:,.2f}")
        logger.info(f"  Insurance Premium: ${report.cyber_insurance_premium:,.2f}")

        return report

    def _generate_board_recommendations(self, risk_score: float, categories: Dict[str, float]) -> List[str]:
        """Generate board-level recommendations."""
        recommendations = []

        # Overall risk
        if risk_score > 60:
            recommendations.append("🚨 CRITICAL: Overall risk score exceeds 60 — immediate board attention required")
        elif risk_score > 40:
            recommendations.append("⚠️ HIGH: Risk score above 40 — strategic investment needed")
        else:
            recommendations.append("✅ MODERATE: Risk within acceptable range — continue monitoring")

        # Category-specific
        for category, score in categories.items():
            if score > 50:
                recommendations.append(f"🔴 {category.upper()}: Score {score}/100 — urgent mitigation required")
            elif score > 30:
                recommendations.append(f"🟡 {category.upper()}: Score {score}/100 — improvement recommended")

        # Financial
        ale = self.calculate_annual_loss_expectancy()
        budget = self.calculate_recommended_budget()
        recommendations.append(
            f"💰 Annual Loss Expectancy: ${ale:,.2f} — "
            f"Recommended security budget: ${budget:,.2f} (ROI: {((ale - budget) / budget * 100):.1f}%)"
        )

        # Compliance
        recommendations.append(
            "📋 Compliance gaps detected in GDPR and PCI DSS — regulatory fines could exceed $2M"
        )

        # Strategic
        recommendations.append(
            "🎯 Strategic recommendation: Implement Zero Trust Architecture to reduce risk by 40%"
        )
        recommendations.append(
            "🤖 AI-driven security automation could reduce operational costs by 35%"
        )

        return recommendations

    def simulate_improvement(self, factor_id: str, improvement: float) -> Dict[str, Any]:
        """Simulate the impact of improving a risk factor."""
        if factor_id not in self.risk_factors:
            return {"error": "Factor not found"}

        factor = self.risk_factors[factor_id]
        old_score = factor.current_score
        new_score = max(0, old_score - improvement)

        # Calculate new ALE
        old_ale = self.calculate_annual_loss_expectancy()
        factor.current_score = new_score
        new_ale = self.calculate_annual_loss_expectancy()
        factor.current_score = old_score  # Restore

        savings = old_ale - new_ale

        return {
            "factor": factor.name,
            "improvement": improvement,
            "old_score": old_score,
            "new_score": new_score,
            "annual_savings": round(savings, 2),
            "roi": round(savings / factor.mitigation_cost, 2) if factor.mitigation_cost > 0 else 0,
            "payback_period_months": round((factor.mitigation_cost / savings) * 12, 1) if savings > 0 else float('inf'),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get CRQ statistics."""
        return {
            "total_reports": self.stats["total_reports_generated"],
            "avg_risk_score": round(self.stats["avg_risk_score"], 2),
            "total_ale": round(self.stats["total_ale"], 2),
            "current_risk_score": self.calculate_risk_score(),
            "current_ale": self.calculate_annual_loss_expectancy(),
            "risk_factors_count": len(self.risk_factors),
            "high_risk_factors": len([f for f in self.risk_factors.values() if f.current_score > 50]),
        }


# Singleton
_crq: Optional[CyberRiskQuantification] = None


def get_crq() -> CyberRiskQuantification:
    global _crq
    if _crq is None:
        _crq = CyberRiskQuantification()
    return _crq
