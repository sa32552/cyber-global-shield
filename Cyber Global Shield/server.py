"""
Cyber Global Shield v2.0 — Autonomous Agentic SIEM Platform
Main FastAPI Application Entry Point
All routes are organized in app/routes/ modules.
"""

from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from app.core.config import settings
from app.core.database import init_db
from app.ingestion.pipeline import get_pipeline
from app.soar.playbook_engine import get_soar
from app.core.websocket_manager import ws_manager as websocket_manager
from app.core.rate_limiter import rate_limit_middleware
from app.routes import api_router

logger = structlog.get_logger(__name__)


# ---- Lifecycle ----

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    logger.info("cyber_global_shield_starting", version=settings.APP_VERSION)

    # Initialize database
    await init_db()

    # Start Kafka consumer in background
    pipeline = get_pipeline()
    consumer_task = asyncio.create_task(pipeline.start_consumer())

    # Start WebSocket manager
    await websocket_manager.start()

    logger.info("cyber_global_shield_started")

    yield

    # Shutdown
    logger.info("cyber_global_shield_shutting_down")
    consumer_task.cancel()
    await get_soar().close()
    await websocket_manager.stop()


app = FastAPI(
    title="Cyber Global Shield",
    version=settings.APP_VERSION,
    description="Autonomous Agentic SIEM Platform — 35 Security Modules | Zero-Day Detection & Real-Time Response",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS - Strict pour production (pas de wildcard)
ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS if hasattr(settings, 'ALLOWED_ORIGINS') else [
    "http://localhost:3000",
    "http://localhost:8000",
    "https://dashboard.cyberglobalshield.com",
    "https://api.cyberglobalshield.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Org-ID"],
)

# Rate Limiting Middleware
app.middleware("http")(rate_limit_middleware)

# Include all route modules
app.include_router(api_router)


# ---- Error Handlers ----

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error("unhandled_exception", error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "status_code": 500},
    )


# ====================================================================
# MAIN ENTRY POINT
# ====================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host=settings.HOST if hasattr(settings, 'HOST') else "0.0.0.0",
        port=settings.PORT if hasattr(settings, 'PORT') else 8000,
        reload=settings.DEBUG if hasattr(settings, 'DEBUG') else False,
        log_level="info",
    )
