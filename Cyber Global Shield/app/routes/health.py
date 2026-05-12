"""
Cyber Global Shield v2.0 — Health, Root & Metrics Endpoints
"""

from datetime import datetime, timezone
import time

from fastapi import APIRouter, Response
import structlog

from app.core.config import settings
from app.core.database import check_db_health
from app.ingestion.pipeline import get_pipeline
from app.soar.playbook_engine import get_soar

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Comprehensive health check."""
    db_ok = await check_db_health()
    pipeline = get_pipeline()
    pipeline_health = await pipeline.health_check()
    soar_health = await get_soar().health_check()

    # Record health check metrics
    from app.core.metrics import metrics
    metrics.increment_counter("health_checks_total", {"status": "ok" if db_ok else "degraded"})

    return {
        "status": "healthy" if db_ok else "degraded",
        "version": settings.APP_VERSION,
        "database": "ok" if db_ok else "error",
        "pipeline": pipeline_health,
        "soar": soar_health,
        "modules_active": 52,
        "quantum_modules": 12,
        "phase_5_10_modules": 10,
        "ultra_modules": 12,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/")
async def root():
    return {
        "name": "Cyber Global Shield",
        "version": settings.APP_VERSION,
        "status": "operational",
        "modules": 52,
        "quantum_modules": 12,
        "phase_5_10_modules": 10,
        "ultra_modules": 12,
        "docs": "/docs",
    }


@router.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics endpoint.

    Returns metrics in Prometheus text format for scraping.
    Configure prometheus.yml to scrape this endpoint.
    """
    from app.core.metrics import metrics, slo_tracker

    output = []
    output.append("# HELP cyber_shield_metrics Cyber Global Shield metrics")
    output.append("# TYPE cyber_shield_metrics untyped")
    output.append("")

    # Counters
    output.append("# HELP cyber_shield_requests_total Total requests by method, endpoint, status")
    output.append("# TYPE cyber_shield_requests_total counter")
    for key, value in metrics._counters.items():
        if key.startswith("api_requests"):
            output.append(f'cyber_shield_requests_total{{{key.split("|", 1)[1] if "|" in key else ""}}} {value}')

    # Gauges
    output.append("# HELP cyber_shield_active_connections Active WebSocket connections")
    output.append("# TYPE cyber_shield_active_connections gauge")
    for key, value in metrics._gauges.items():
        output.append(f'cyber_shield_{key} {value}')

    # ML-specific metrics
    output.append("# HELP cyber_shield_ml_inference_ms ML model inference time in milliseconds")
    output.append("# TYPE cyber_shield_ml_inference_ms histogram")
    for key, stats in metrics._histograms.items():
        if key.startswith("ml_inference"):
            output.append(f'cyber_shield_ml_inference_ms_count{{{key.split("|", 1)[1] if "|" in key else ""}}} {stats["count"]}')
            output.append(f'cyber_shield_ml_inference_ms_p99{{{key.split("|", 1)[1] if "|" in key else ""}}} {stats["p99"]}')

    # Pipeline metrics
    output.append("# HELP cyber_shield_pipeline_events_total Total events processed by pipeline")
    output.append("# TYPE cyber_shield_pipeline_events_total counter")
    pipeline = get_pipeline()
    output.append(f'cyber_shield_pipeline_events_total {pipeline._total_ingested}')
    output.append(f'cyber_shield_pipeline_errors_total {pipeline._total_failed}')

    # SLO metrics
    output.append("# HELP cyber_shield_slo_ratio SLO compliance ratio (0.0-1.0)")
    output.append("# TYPE cyber_shield_slo_ratio gauge")
    for slo_name, slo_data in slo_tracker._slos.items():
        ratio = slo_tracker.get_compliance(slo_name)
        output.append(f'cyber_shield_slo_ratio{{slo="{slo_name}"}} {ratio}')

    # Uptime
    output.append("# HELP cyber_shield_uptime_seconds Application uptime in seconds")
    output.append("# TYPE cyber_shield_uptime_seconds gauge")
    output.append(f'cyber_shield_uptime_seconds {time.time() - metrics._start_time}')

    output.append("")
    return Response(
        content="\n".join(output),
        media_type="text/plain",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
