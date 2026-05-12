"""
Cyber Global Shield v2.0 — Autonomous Agents (CrewAI) Endpoints
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends
import structlog

from app.core.security import get_current_user, User
from app.agents.crew import get_crew

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.post("/triage")
async def agent_triage(
    alert: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
    current_user: User = Depends(get_current_user),
):
    """Run triage agent on an alert."""
    crew = get_crew()
    result = await crew.triage_alert(alert, context)
    return result.model_dump()


@router.post("/investigate")
async def agent_investigate(
    alert: Dict[str, Any],
    logs: List[Dict[str, Any]],
    iocs: Optional[Dict[str, Any]] = None,
    current_user: User = Depends(get_current_user),
):
    """Run investigation agent on an alert."""
    crew = get_crew()
    result = await crew.investigate(alert, logs, iocs)
    return result.model_dump()


@router.post("/pipeline")
async def agent_full_pipeline(
    alert: Dict[str, Any],
    logs: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    current_user: User = Depends(get_current_user),
):
    """Run the complete autonomous SOC pipeline."""
    crew = get_crew()
    result = await crew.run_full_pipeline(alert, logs, context)
    return result
