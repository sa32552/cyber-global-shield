"""
Cyber Global Shield v2.0 — Log Ingestion Endpoints
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, BackgroundTasks, Query
from pydantic import BaseModel, Field
import structlog

from app.core.security import get_current_user, User
from app.ingestion.pipeline import get_pipeline

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


class LogIngestRequest(BaseModel):
    org_id: str
    source: str
    event_type: str
    severity: Optional[str] = "info"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    tags: Optional[List[str]] = []
    raw_payload: Optional[Dict[str, Any]] = {}
    timestamp: Optional[str] = None


class LogBatchRequest(BaseModel):
    logs: List[LogIngestRequest]


@router.post("/log")
async def ingest_log(
    request: LogIngestRequest,
    background_tasks: BackgroundTasks,
):
    """Ingest a single log event."""
    pipeline = get_pipeline()
    log_data = request.model_dump()
    success = await pipeline.ingest(log_data)
    return {"status": "accepted" if success else "error"}


@router.post("/batch")
async def ingest_logs_batch(
    request: LogBatchRequest,
    background_tasks: BackgroundTasks,
):
    """Ingest a batch of log events."""
    pipeline = get_pipeline()
    logs = [log.model_dump() for log in request.logs]
    count = await pipeline.ingest_batch(logs)
    return {"status": "accepted", "count": count, "total": len(logs)}


@router.get("/stats")
async def get_ingestion_stats(
    org_id: str = Query(...),
    minutes: int = Query(60, ge=1, le=1440),
    current_user: User = Depends(get_current_user),
):
    """Get ingestion statistics for dashboard."""
    pipeline = get_pipeline()
    return await pipeline.get_stats(org_id, minutes)
