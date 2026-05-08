"""
Cyber Global Shield — LLM Cost Monitoring
Surveille et optimise les coûts d'utilisation des API LLM (OpenAI, Anthropic, etc.).
"""

import json
import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    LOCAL = "local"


class LLMRequest(BaseModel):
    """Record of an LLM API request."""
    id: str
    provider: LLMProvider
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    duration_ms: int
    endpoint: str
    user_id: Optional[str] = None
    org_id: Optional[str] = None
    timestamp: datetime = datetime.utcnow()
    success: bool = True
    error: Optional[str] = None


# Cost per 1K tokens (USD)
COST_TABLE = {
    "gpt-4": {"prompt": 0.03, "completion": 0.06},
    "gpt-4-turbo": {"prompt": 0.01, "completion": 0.03},
    "gpt-4o": {"prompt": 0.005, "completion": 0.015},
    "gpt-3.5-turbo": {"prompt": 0.001, "completion": 0.002},
    "claude-3-opus": {"prompt": 0.015, "completion": 0.075},
    "claude-3-sonnet": {"prompt": 0.003, "completion": 0.015},
    "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125},
    "default": {"prompt": 0.01, "completion": 0.03},
}


class LLMCostMonitor:
    """
    Monitors and tracks LLM API usage and costs.
    Provides budget alerts and optimization recommendations.
    """

    def __init__(self):
        self._requests: List[LLMRequest] = []
        self._max_history = 100000
        self._budget_alerts: List[Dict] = []
        self._daily_budget: Optional[float] = None
        self._monthly_budget: Optional[float] = None

    def set_budgets(self, daily: Optional[float] = None, monthly: Optional[float] = None):
        """Set daily and monthly budget limits."""
        self._daily_budget = daily
        self._monthly_budget = monthly
        logger.info(f"LLM budgets set: daily=${daily}, monthly=${monthly}")

    def record_request(
        self,
        provider: LLMProvider,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        duration_ms: int,
        endpoint: str = "",
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> LLMRequest:
        """Record an LLM API request and calculate cost."""
        total_tokens = prompt_tokens + completion_tokens

        # Calculate cost
        cost_table = COST_TABLE.get(model, COST_TABLE["default"])
        cost = (
            (prompt_tokens / 1000) * cost_table["prompt"]
            + (completion_tokens / 1000) * cost_table["completion"]
        )

        request = LLMRequest(
            id=f"llm_{int(time.time())}_{len(self._requests)}",
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=round(cost, 6),
            duration_ms=duration_ms,
            endpoint=endpoint,
            user_id=user_id,
            org_id=org_id,
            success=success,
            error=error,
        )

        self._requests.append(request)
        if len(self._requests) > self._max_history:
            self._requests = self._requests[-self._max_history:]

        # Check budgets
        self._check_budgets()

        return request

    def _check_budgets(self):
        """Check if budgets are exceeded."""
        now = datetime.utcnow()

        # Daily check
        if self._daily_budget:
            daily_cost = self.get_cost_since(now - timedelta(days=1))
            if daily_cost > self._daily_budget:
                alert = {
                    "type": "daily_budget_exceeded",
                    "budget": self._daily_budget,
                    "actual": daily_cost,
                    "timestamp": now,
                }
                self._budget_alerts.append(alert)
                logger.warning(
                    f"Daily LLM budget exceeded: ${daily_cost:.2f} > ${self._daily_budget:.2f}"
                )

        # Monthly check
        if self._monthly_budget:
            monthly_cost = self.get_cost_since(now - timedelta(days=30))
            if monthly_cost > self._monthly_budget:
                alert = {
                    "type": "monthly_budget_exceeded",
                    "budget": self._monthly_budget,
                    "actual": monthly_cost,
                    "timestamp": now,
                }
                self._budget_alerts.append(alert)
                logger.warning(
                    f"Monthly LLM budget exceeded: ${monthly_cost:.2f} > ${self._monthly_budget:.2f}"
                )

    def get_cost_since(self, since: datetime) -> float:
        """Get total cost since a given time."""
        return sum(
            r.cost_usd for r in self._requests
            if r.timestamp >= since
        )

    def get_stats(
        self,
        since: Optional[datetime] = None,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get LLM usage statistics."""
        filtered = self._requests
        if since:
            filtered = [r for r in filtered if r.timestamp >= since]
        if org_id:
            filtered = [r for r in filtered if r.org_id == org_id]

        if not filtered:
            return {
                "total_requests": 0,
                "total_cost": 0.0,
                "total_tokens": 0,
                "avg_duration_ms": 0,
                "error_rate": 0.0,
                "models": {},
                "providers": {},
            }

        total_cost = sum(r.cost_usd for r in filtered)
        total_tokens = sum(r.total_tokens for r in filtered)
        errors = sum(1 for r in filtered if not r.success)

        # Per-model stats
        model_stats = {}
        for r in filtered:
            if r.model not in model_stats:
                model_stats[r.model] = {
                    "requests": 0, "cost": 0.0, "tokens": 0,
                }
            model_stats[r.model]["requests"] += 1
            model_stats[r.model]["cost"] += r.cost_usd
            model_stats[r.model]["tokens"] += r.total_tokens

        # Per-provider stats
        provider_stats = {}
        for r in filtered:
            if r.provider not in provider_stats:
                provider_stats[r.provider] = {
                    "requests": 0, "cost": 0.0,
                }
            provider_stats[r.provider]["requests"] += 1
            provider_stats[r.provider]["cost"] += r.cost_usd

        return {
            "total_requests": len(filtered),
            "total_cost": round(total_cost, 4),
            "total_tokens": total_tokens,
            "avg_cost_per_request": round(total_cost / len(filtered), 6),
            "avg_tokens_per_request": total_tokens // len(filtered),
            "avg_duration_ms": sum(r.duration_ms for r in filtered) // len(filtered),
            "error_rate": round(errors / len(filtered), 4),
            "models": model_stats,
            "providers": provider_stats,
        }

    def get_daily_report(self) -> List[Dict[str, Any]]:
        """Get daily cost breakdown for the last 30 days."""
        now = datetime.utcnow()
        daily_costs = []

        for i in range(30):
            day_start = now - timedelta(days=i + 1)
            day_end = now - timedelta(days=i)
            cost = self.get_cost_since(day_start) - self.get_cost_since(day_end)

            daily_costs.append({
                "date": day_start.strftime("%Y-%m-%d"),
                "cost": round(cost, 4),
            })

        return daily_costs

    def get_optimization_tips(self) -> List[str]:
        """Get cost optimization recommendations."""
        tips = []
        stats = self.get_stats(since=datetime.utcnow() - timedelta(days=7))

        if not stats["total_requests"]:
            return ["No LLM usage data available for optimization analysis."]

        # Check for expensive model usage
        for model, mstats in stats["models"].items():
            if mstats["cost"] > 0:
                avg_cost = mstats["cost"] / mstats["requests"]
                if avg_cost > 0.01:
                    tips.append(
                        f"💰 Model '{model}' has high avg cost (${avg_cost:.4f}/req). "
                        f"Consider using a cheaper model for simple tasks."
                    )

        # Check error rate
        if stats["error_rate"] > 0.05:
            tips.append(
                f"⚠️ High error rate ({stats['error_rate']*100:.1f}%). "
                f"Check API configuration and rate limits."
            )

        # Check for model downgrade opportunities
        if "gpt-4" in stats["models"] and "gpt-3.5-turbo" not in stats["models"]:
            tips.append(
                "💡 Consider using GPT-3.5-Turbo for non-critical tasks "
                "to reduce costs by up to 90%."
            )

        # Check cache opportunities
        if stats["total_tokens"] > 100000:
            tips.append(
                "💡 Implement response caching for repeated queries "
                "to reduce token usage."
            )

        if not tips:
            tips.append("✅ LLM usage is well optimized!")

        return tips

    def get_budget_alerts(self) -> List[Dict]:
        """Get budget alerts."""
        return self._budget_alerts[-10:]  # Last 10 alerts

    def get_usage_by_user(self, org_id: Optional[str] = None) -> List[Dict]:
        """Get usage breakdown by user."""
        filtered = self._requests
        if org_id:
            filtered = [r for r in filtered if r.org_id == org_id]

        user_stats = {}
        for r in filtered:
            uid = r.user_id or "anonymous"
            if uid not in user_stats:
                user_stats[uid] = {
                    "user_id": uid,
                    "requests": 0,
                    "cost": 0.0,
                    "tokens": 0,
                }
            user_stats[uid]["requests"] += 1
            user_stats[uid]["cost"] += r.cost_usd
            user_stats[uid]["tokens"] += r.total_tokens

        return sorted(
            user_stats.values(),
            key=lambda x: x["cost"],
            reverse=True,
        )


# Global LLM cost monitor
llm_cost_monitor = LLMCostMonitor()
