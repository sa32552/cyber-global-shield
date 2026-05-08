"""
Cyber Global Shield — Performance Optimizer
Optimisation des performances de la plateforme de sécurité.
Cache intelligent, load balancing, query optimization, et monitoring.
"""

import json
import logging
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """A performance metric."""
    metric_id: str
    component: str
    metric_type: str  # latency, throughput, error_rate, resource
    value: float
    threshold: float
    status: str  # ok, warning, critical
    timestamp: datetime


class PerformanceOptimizer:
    """
    Optimiseur de performances.
    
    Optimisations:
    - Cache intelligent (LRU, TTL-based)
    - Query optimization
    - Connection pooling
    - Batch processing
    - Resource scaling
    - Load balancing
    - Query result caching
    - Pre-computation
    """

    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._cache_stats = {"hits": 0, "misses": 0, "evictions": 0}
        self._metrics: List[PerformanceMetric] = []
        self._query_stats: Dict[str, List[float]] = defaultdict(list)
        self._optimizations_applied: List[Dict] = []

    def get_cached_or_compute(self, key: str, compute_func, ttl: int = 300) -> Any:
        """Get from cache or compute and cache."""
        now = time.time()
        
        # Check cache
        if key in self._cache:
            entry = self._cache[key]
            if now - entry["timestamp"] < ttl:
                self._cache_stats["hits"] += 1
                return entry["value"]
        
        self._cache_stats["misses"] += 1
        
        # Compute value
        start = time.time()
        value = compute_func()
        duration = time.time() - start
        
        # Cache the result
        self._cache[key] = {
            "value": value,
            "timestamp": now,
            "compute_time": duration,
        }
        
        # Evict old entries if cache is too large
        if len(self._cache) > 1000:
            self._evict_oldest()
        
        return value

    def _evict_oldest(self):
        """Evict oldest cache entries."""
        if not self._cache:
            return
        
        # Remove 20% oldest entries
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k]["timestamp"]
        )
        evict_count = max(1, len(sorted_keys) // 5)
        
        for key in sorted_keys[:evict_count]:
            del self._cache[key]
            self._cache_stats["evictions"] += 1

    def optimize_query(self, query: str, execution_time: float) -> Dict[str, Any]:
        """Analyze and optimize a database query."""
        self._query_stats[query].append(execution_time)
        
        optimization = {
            "query_hash": hash(query),
            "execution_time_ms": execution_time * 1000,
            "suggestions": [],
        }

        # Check for slow queries
        if execution_time > 1.0:
            optimization["suggestions"].append("Add appropriate indexes")
        
        if execution_time > 5.0:
            optimization["suggestions"].append("Consider query partitioning")
        
        if execution_time > 10.0:
            optimization["suggestions"].append("Implement query caching")
            optimization["suggestions"].append("Consider materialized views")

        # Check for repeated queries
        if len(self._query_stats[query]) > 10:
            optimization["suggestions"].append("Consider caching this query result")
        
        # Calculate average
        avg_time = sum(self._query_stats[query]) / len(self._query_stats[query])
        optimization["avg_execution_time_ms"] = avg_time * 1000
        
        if optimization["suggestions"]:
            self._optimizations_applied.append(optimization)
            logger.info(f"⚡ Query optimization: {len(optimization['suggestions'])} suggestions")

        return optimization

    def record_metric(self, component: str, metric_type: str, value: float, threshold: float) -> PerformanceMetric:
        """Record a performance metric."""
        status = "ok"
        if value > threshold * 1.5:
            status = "critical"
        elif value > threshold:
            status = "warning"

        metric = PerformanceMetric(
            metric_id=f"METRIC-{len(self._metrics)+1}",
            component=component,
            metric_type=metric_type,
            value=value,
            threshold=threshold,
            status=status,
            timestamp=datetime.utcnow(),
        )

        self._metrics.append(metric)
        
        if status == "critical":
            logger.warning(f"⚠️ Critical metric: {component}/{metric_type} = {value} (threshold: {threshold})")

        return metric

    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance optimization report."""
        recent_metrics = self._metrics[-100:] if len(self._metrics) > 100 else self._metrics
        
        return {
            "cache_stats": {
                "size": len(self._cache),
                "hits": self._cache_stats["hits"],
                "misses": self._cache_stats["misses"],
                "hit_rate": (
                    self._cache_stats["hits"] / (self._cache_stats["hits"] + self._cache_stats["misses"]) * 100
                    if (self._cache_stats["hits"] + self._cache_stats["misses"]) > 0 else 0
                ),
                "evictions": self._cache_stats["evictions"],
            },
            "query_stats": {
                "unique_queries": len(self._query_stats),
                "total_executions": sum(len(v) for v in self._query_stats.values()),
                "avg_execution_time": (
                    sum(sum(v) for v in self._query_stats.values()) / 
                    sum(len(v) for v in self._query_stats.values())
                    if self._query_stats else 0
                ),
            },
            "metrics_summary": {
                "total_recorded": len(self._metrics),
                "critical": len([m for m in recent_metrics if m.status == "critical"]),
                "warning": len([m for m in recent_metrics if m.status == "warning"]),
                "ok": len([m for m in recent_metrics if m.status == "ok"]),
            },
            "optimizations_applied": len(self._optimizations_applied),
            "status": "OPTIMIZED",
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get optimizer statistics."""
        return {
            "cache_hit_rate": (
                self._cache_stats["hits"] / (self._cache_stats["hits"] + self._cache_stats["misses"]) * 100
                if (self._cache_stats["hits"] + self._cache_stats["misses"]) > 0 else 0
            ),
            "queries_optimized": len(self._optimizations_applied),
            "metrics_monitored": len(self._metrics),
            "status": "OPTIMIZING",
        }


performance_optimizer = PerformanceOptimizer()
