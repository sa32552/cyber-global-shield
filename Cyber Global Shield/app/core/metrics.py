"""
╔══════════════════════════════════════════════════════════════╗
║  Cyber Global Shield — Metrics & SLO Tracker                ║
║  Métriques Prometheus avancées avec SLO tracking            ║
║  Rate / Errors / Duration / Saturation (4 signaux d'or)     ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    from app.core.metrics import metrics, slo_tracker
    
    # Record API request
    metrics.api_requests.labels(method="GET", endpoint="/health", status="200").inc()
    
    # Record ML inference
    metrics.ml_inference.labels(model="anomaly_detector", version="v2").observe(0.045)
    
    # Track SLO
    slo_tracker.record_sli("api_latency_p99", 0.3)
"""

import os
import time
import structlog
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import defaultdict, deque
from datetime import datetime, timedelta

logger = structlog.get_logger(__name__)


# =============================================================================
# Prometheus Metrics
# =============================================================================

class MetricsCollector:
    """
    Collecteur de métriques compatible Prometheus.
    Utilise les 4 signaux d'or : Latency, Traffic, Errors, Saturation.
    """

    def __init__(self):
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._start_time = time.time()

    # ─── Counters ────────────────────────────────────────────────

    def increment_counter(self, name: str, labels: Dict[str, str] = None, value: int = 1):
        """Increment a counter metric."""
        key = self._metric_key(name, labels)
        self._counters[key] += value

    def get_counter(self, name: str, labels: Dict[str, str] = None) -> int:
        """Get counter value."""
        key = self._metric_key(name, labels)
        return self._counters.get(key, 0)

    # ─── Gauges ──────────────────────────────────────────────────

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric."""
        key = self._metric_key(name, labels)
        self._gauges[key] = value

    def get_gauge(self, name: str, labels: Dict[str, str] = None) -> float:
        """Get gauge value."""
        key = self._metric_key(name, labels)
        return self._gauges.get(key, 0.0)

    # ─── Histograms ──────────────────────────────────────────────

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value for histogram metric."""
        key = self._metric_key(name, labels)
        self._histograms[key].append(value)
        # Keep only last 1000 values
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-1000:]

    def get_histogram_stats(self, name: str, labels: Dict[str, str] = None) -> Dict[str, float]:
        """Get histogram statistics."""
        key = self._metric_key(name, labels)
        values = self._histograms.get(key, [])
        if not values:
            return {"count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_values = sorted(values)
        n = len(sorted_values)
        return {
            "count": n,
            "min": sorted_values[0],
            "max": sorted_values[-1],
            "avg": sum(sorted_values) / n,
            "p50": sorted_values[int(n * 0.50)],
            "p95": sorted_values[int(n * 0.95)],
            "p99": sorted_values[int(n * 0.99)],
        }

    # ─── Prometheus Format ───────────────────────────────────────

    def to_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        lines.append("# HELP cgs_uptime_seconds Cyber Global Shield uptime")
        lines.append("# TYPE cgs_uptime_seconds gauge")
        lines.append(f"cgs_uptime_seconds {time.time() - self._start_time}")

        # Counters
        for key, value in self._counters.items():
            name, labels_str = self._parse_metric_key(key)
            lines.append(f"# HELP {name} Counter metric")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name}{{{labels_str}}} {value}")

        # Gauges
        for key, value in self._gauges.items():
            name, labels_str = self._parse_metric_key(key)
            lines.append(f"# HELP {name} Gauge metric")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{{{labels_str}}} {value}")

        # Histograms
        for key, values in self._histograms.items():
            name, labels_str = self._parse_metric_key(key)
            lines.append(f"# HELP {name} Histogram metric")
            lines.append(f"# TYPE {name} histogram")
            for v in values[-10:]:  # Last 10 values
                lines.append(f"{name}{{{labels_str}}} {v}")

        return "\n".join(lines)

    def _metric_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Generate a metric key with labels."""
        if labels:
            labels_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
            return f"{name}|{labels_str}"
        return f"{name}|"

    def _parse_metric_key(self, key: str) -> tuple:
        """Parse metric key back to name and labels string."""
        if "|" in key:
            name, labels_str = key.split("|", 1)
            return name, labels_str
        return key, ""

    def get_stats(self) -> Dict[str, Any]:
        """Get metrics collector statistics."""
        return {
            "uptime_seconds": time.time() - self._start_time,
            "counters": len(self._counters),
            "gauges": len(self._gauges),
            "histograms": {k: len(v) for k, v in self._histograms.items()},
        }


# =============================================================================
# SLO Tracker
# =============================================================================

@dataclass
class SLOConfig:
    """Service Level Objective configuration."""
    name: str
    target: float  # e.g., 0.5 for 500ms
    window_seconds: int = 86400  # 24h rolling window
    budget: float = 1.0  # 100% error budget


class SLOTracker:
    """
    Track Service Level Objectives en temps réel.
    
    SLOs surveillés:
    - api_latency_p99: 500ms
    - api_error_rate: 0.1%
    - ml_inference_p99: 1s
    - pipeline_latency_p99: 5s
    - uptime: 99.99%
    """

    def __init__(self):
        self._slos: Dict[str, SLOConfig] = {
            "api_latency_p99": SLOConfig("api_latency_p99", 0.5, 86400, 1.0),
            "api_error_rate": SLOConfig("api_error_rate", 0.001, 86400, 1.0),
            "ml_inference_p99": SLOConfig("ml_inference_p99", 1.0, 86400, 1.0),
            "pipeline_latency_p99": SLOConfig("pipeline_latency_p99", 5.0, 86400, 1.0),
            "uptime": SLOConfig("uptime", 0.9999, 86400, 1.0),
        }
        self._sli_history: Dict[str, deque] = {
            name: deque(maxlen=10000)
            for name in self._slos
        }
        self._error_budget: Dict[str, float] = {
            name: config.budget
            for name, config in self._slos.items()
        }
        self._last_burn_rate: Dict[str, float] = {}

    def record_sli(self, name: str, value: float):
        """
        Record a Service Level Indicator.
        
        Args:
            name: SLO name (e.g., "api_latency_p99")
            value: Measured value
        """
        if name not in self._slos:
            logger.warning("unknown_slo", name=name)
            return

        config = self._slos[name]
        self._sli_history[name].append({
            "timestamp": time.time(),
            "value": value,
        })

        # Check if SLO is breached
        if value > config.target:
            # Consume error budget (proportional to breach severity)
            breach_ratio = (value - config.target) / config.target
            consumption = breach_ratio * 0.001  # 0.1% per breach unit
            self._error_budget[name] = max(0, self._error_budget[name] - consumption)

            if self._error_budget[name] <= 0:
                logger.warning(
                    "slo_error_budget_exhausted",
                    slo=name,
                    value=value,
                    target=config.target,
                )

    def record_api_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record an API request and update SLOs."""
        # API latency SLO
        self.record_sli("api_latency_p99", duration)

        # API error rate SLO
        if status >= 500:
            self.record_sli("api_error_rate", 1.0)
        else:
            self.record_sli("api_error_rate", 0.0)

    def record_ml_inference(self, model: str, version: str, duration: float):
        """Record ML inference and update SLOs."""
        self.record_sli("ml_inference_p99", duration)

    def record_pipeline_latency(self, latency: float):
        """Record pipeline latency and update SLOs."""
        self.record_sli("pipeline_latency_p99", latency)

    def get_slo_status(self, name: str) -> Dict[str, Any]:
        """Get current SLO status."""
        if name not in self._slos:
            return {"error": f"SLO {name} not found"}

        config = self._slos[name]
        history = list(self._sli_history.get(name, []))
        
        # Calculate current compliance
        if history:
            window_start = time.time() - config.window_seconds
            recent = [h for h in history if h["timestamp"] > window_start]
            breaches = sum(1 for h in recent if h["value"] > config.target)
            total = len(recent)
            compliance = (total - breaches) / max(total, 1) * 100
        else:
            compliance = 100.0

        # Calculate burn rate
        if len(history) >= 2:
            time_span = history[-1]["timestamp"] - history[0]["timestamp"]
            if time_span > 0:
                burn_rate = len([h for h in history if h["value"] > config.target]) / time_span
            else:
                burn_rate = 0
        else:
            burn_rate = 0

        return {
            "name": name,
            "target": config.target,
            "current_compliance_pct": round(compliance, 2),
            "error_budget_remaining": round(self._error_budget.get(name, 1.0) * 100, 2),
            "error_budget_consumed_pct": round((1 - self._error_budget.get(name, 1.0)) * 100, 2),
            "burn_rate": round(burn_rate, 4),
            "window_hours": config.window_seconds / 3600,
            "total_measurements": len(history),
            "recent_breaches": breaches if history else 0,
        }

    def get_all_slos(self) -> Dict[str, Any]:
        """Get status of all SLOs."""
        return {
            name: self.get_slo_status(name)
            for name in self._slos
        }

    def get_budget_report(self) -> Dict[str, float]:
        """Get remaining error budget for all SLOs."""
        return {
            name: max(0, budget)
            for name, budget in self._error_budget.items()
        }

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get active SLO alerts."""
        alerts = []
        for name, config in self._slos.items():
            budget = self._error_budget.get(name, 1.0)
            if budget <= 0:
                alerts.append({
                    "slo": name,
                    "severity": "CRITICAL",
                    "message": f"SLO {name} error budget exhausted",
                    "budget_remaining": 0,
                })
            elif budget < 0.5:
                alerts.append({
                    "slo": name,
                    "severity": "WARNING",
                    "message": f"SLO {name} error budget below 50%",
                    "budget_remaining": round(budget * 100, 2),
                })
        return alerts


# =============================================================================
# Global instances
# =============================================================================

metrics = MetricsCollector()
slo_tracker = SLOTracker()
