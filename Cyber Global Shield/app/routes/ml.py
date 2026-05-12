"""
Cyber Global Shield v2.0 — Machine Learning & Federated Learning Endpoints
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
import structlog

from app.core.config import settings
from app.core.security import get_current_user, User, require_role
from app.ml.anomaly_detector import create_default_detector
from app.fl.federated_server import create_federated_server

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["machine-learning"])


class MLEntryRequest(BaseModel):
    logs: List[Dict[str, Any]]
    threshold: Optional[float] = None


class FLTrainRequest(BaseModel):
    num_rounds: int = 10
    min_clients: int = 2


@router.post("/ml/detect")
async def detect_anomalies(
    request: MLEntryRequest,
    current_user: User = Depends(get_current_user),
):
    """Run ML anomaly detection on a sequence of logs."""
    detector = create_default_detector()
    result = detector.detect(request.logs, threshold=request.threshold)
    return {
        "anomaly_score": result.anomaly_score,
        "is_anomaly": result.is_anomaly,
        "reconstruction_error": result.reconstruction_error,
        "threshold_used": result.threshold_used,
        "explanation": result.explanation,
        "feature_scores": result.feature_scores,
        "inference_time_ms": result.inference_time_ms,
    }


@router.post("/ml/calibrate")
async def calibrate_threshold(
    normal_data: List[List[Dict[str, Any]]],
    percentile: float = Query(99.0, ge=50.0, le=100.0),
    current_user: User = Depends(require_role("admin", "ml_engineer")),
):
    """Calibrate anomaly detection threshold using normal data."""
    detector = create_default_detector()
    threshold = detector.calibrate_threshold(normal_data, percentile)
    return {"threshold": threshold, "percentile": percentile, "samples": len(normal_data)}


@router.post("/fl/train")
async def start_federated_training(
    request: FLTrainRequest,
    current_user: User = Depends(require_role("admin", "ml_engineer")),
):
    """Start a federated learning training round."""
    server = create_federated_server(
        server_address=settings.FLOWER_SERVER_ADDRESS,
        num_rounds=request.num_rounds,
        min_clients=request.min_clients,
    )
    return {
        "status": "initiated",
        "server_address": settings.FLOWER_SERVER_ADDRESS,
        "num_rounds": request.num_rounds,
        "min_clients": request.min_clients,
        "note": "Federated server running. Clients can now connect.",
    }


@router.get("/fl/stats")
async def get_fl_stats(
    current_user: User = Depends(get_current_user),
):
    """Get federated learning statistics."""
    server = create_federated_server()
    return server.get_stats()
