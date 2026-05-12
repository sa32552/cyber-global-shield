"""
Cyber Global Shield v2.0 — Dashboard & Analytics Endpoints
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
import structlog

from app.core.security import get_current_user, User
from app.ingestion.clickhouse_client import get_clickhouse

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/overview")
async def dashboard_overview(
    org_id: str = Query(...),
    current_user: User = Depends(get_current_user),
):
    """Get dashboard overview data."""
    ch = get_clickhouse()
    stats = ch.get_traffic_stats(org_id, minutes=1440)
    alerts = ch.query_logs(
        org_id=org_id,
        start_time=datetime.now(timezone.utc) - timedelta(hours=24),
        filters={"severity": "critical"},
        limit=10,
    )

    return {
        "traffic_stats": stats,
        "critical_alerts_24h": len(alerts),
        "latest_alerts": alerts[:5],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/alerts")
async def dashboard_alerts(
    org_id: str = Query(...),
    severity: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    hours: int = Query(24),
    limit: int = Query(100),
    current_user: User = Depends(get_current_user),
):
    """Search and filter alerts."""
    ch = get_clickhouse()
    filters = {}
    if severity:
        filters["severity"] = severity
    if alert_type:
        filters["event_type"] = alert_type

    logs = ch.query_logs(
        org_id=org_id,
        start_time=datetime.now(timezone.utc) - timedelta(hours=hours),
        limit=limit,
        filters=filters,
    )
    return {"count": len(logs), "alerts": logs}
