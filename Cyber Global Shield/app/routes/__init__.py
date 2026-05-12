"""
Cyber Global Shield v2.0 — Route Modules
Aggregates all API routers into a single include for app.py.
"""

from fastapi import APIRouter

from app.routes.health import router as health_router
from app.routes.auth import router as auth_router
from app.routes.ingestion import router as ingestion_router
from app.routes.ml import router as ml_router
from app.routes.agents import router as agents_router
from app.routes.soar import router as soar_router
from app.routes.dashboard import router as dashboard_router
from app.routes.security_modules import router as security_router
from app.routes.quantum import router as quantum_router
from app.routes.advanced import router as advanced_router
from app.routes.ultra import router as ultra_router

api_router = APIRouter()

# Include all sub-routers
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(ingestion_router)
api_router.include_router(ml_router)
api_router.include_router(agents_router)
api_router.include_router(soar_router)
api_router.include_router(dashboard_router)
api_router.include_router(security_router)
api_router.include_router(quantum_router)
api_router.include_router(advanced_router)
api_router.include_router(ultra_router)

__all__ = ["api_router"]
