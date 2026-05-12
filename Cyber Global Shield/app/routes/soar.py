"""
Cyber Global Shield v2.0 — SOAR (Security Orchestration, Automation & Response) Endpoints
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import structlog

from app.core.security import get_current_user, User
from app.soar.playbook_engine import get_soar

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/soar", tags=["soar"])


class SOARExecuteRequest(BaseModel):
    playbook_name: str
    alert: Dict[str, Any]
    iocs: Optional[Dict[str, Any]] = {}
    affected_assets: Optional[List[str]] = []
    compromised_users: Optional[List[str]] = []
    dry_run: bool = False
    human_approved: bool = False


@router.get("/playbooks")
async def list_playbooks(
    current_user: User = Depends(get_current_user),
):
    """List all available SOAR playbooks."""
    soar = get_soar()
    return await soar.get_available_playbooks()


@router.post("/execute")
async def execute_playbook(
    request: SOARExecuteRequest,
    current_user: User = Depends(get_current_user),
):
    """Execute a SOAR playbook."""
    soar = get_soar()

    playbook = soar.playbooks.get(request.playbook_name)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook {request.playbook_name} not found")

    if playbook.requires_approval and not request.human_approved:
        return {
            "status": "pending_approval",
            "playbook": request.playbook_name,
            "message": "This playbook requires human approval. Set human_approved=true to execute.",
        }

    context = {
        "alert": request.alert,
        "iocs": request.iocs or {},
        "affected_assets": request.affected_assets or [],
        "compromised_users": request.compromised_users or [],
    }

    result = await soar.execute_playbook(
        playbook_name=request.playbook_name,
        context=context,
        dry_run=request.dry_run,
    )

    return {
        "playbook": result.playbook_name,
        "trigger": result.trigger_event,
        "status": result.status.value,
        "duration_ms": result.total_duration_ms,
        "actions": [
            {
                "name": ar.action_name,
                "status": ar.status.value,
                "duration_ms": ar.duration_ms,
                "error": ar.error,
            }
            for ar in result.actions_results
        ],
    }
