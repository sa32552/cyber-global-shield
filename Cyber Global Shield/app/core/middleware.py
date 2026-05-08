"""
Cyber Global Shield — Security Middleware
CORS restreint, Security Headers, HTTPS redirect, Request logging, ELK integration.
"""

import time
import uuid
from typing import Optional, Callable
from datetime import datetime, timezone

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings

logger = structlog.get_logger(__name__)


# =============================================================================
# Structured Logging Configuration (ELK-compatible)
# =============================================================================

def configure_logging():
    """Configure structured logging for ELK stack integration."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            # JSON output for ELK (Filebeat/Logstash)
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# =============================================================================
# Security Headers Middleware
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to all responses.
    Implements OWASP security best practices.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # OWASP Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; "
            "img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' http://localhost:8000 ws://localhost:8000; "
            "frame-ancestors 'none';"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"

        # Remove server fingerprinting
        if "Server" in response.headers:
            del response.headers["Server"]

        return response


# =============================================================================
# Request Logging Middleware (ELK-compatible)
# =============================================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs all requests in structured JSON format for ELK stack.
    Compatible with Filebeat → Logstash → Elasticsearch → Kibana.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Request timing
        start_time = time.time()
        method = request.method
        path = request.url.path
        query_params = str(request.query_params)
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        # Process request
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            logger.error(
                "request_failed",
                request_id=request_id,
                method=method,
                path=path,
                error=str(e),
                client_ip=client_ip,
            )
            raise

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Structured log entry for ELK
        log_entry = {
            "type": "api_request",
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "query_params": query_params,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "content_length": response.headers.get("content-length", 0),
            "service": "cyber-global-shield-api",
            "environment": settings.ENVIRONMENT,
        }

        # Log based on status code
        if status_code >= 500:
            logger.error("request_error", **log_entry)
        elif status_code >= 400:
            logger.warning("request_warning", **log_entry)
        else:
            logger.info("request_success", **log_entry)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


# =============================================================================
# HTTPS Redirect Middleware
# =============================================================================

class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """
    Redirects HTTP to HTTPS in production.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if settings.ENVIRONMENT == "production":
            # Check if request is HTTPS
            forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
            if forwarded_proto != "https" and request.url.scheme != "https":
                # Redirect to HTTPS
                https_url = str(request.url).replace("http://", "https://", 1)
                return Response(
                    status_code=301,
                    headers={"Location": https_url},
                )

        return await call_next(request)


# =============================================================================
# CORS Configuration
# =============================================================================

def configure_cors(app: FastAPI):
    """
    Configure CORS with restricted origins.
    Replaces the permissive allow_origins=["*"].
    """
    # Allowed origins based on environment
    if settings.ENVIRONMENT == "production":
        allowed_origins = [
            "https://cyber-global-shield.com",
            "https://app.cyber-global-shield.com",
            "https://api.cyber-global-shield.com",
            "https://admin.cyber-global-shield.com",
        ]
    elif settings.ENVIRONMENT == "staging":
        allowed_origins = [
            "https://staging.cyber-global-shield.com",
            "http://localhost:3000",
            "http://localhost:8000",
        ]
    else:
        # Development — allow localhost
        allowed_origins = [
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
            "http://localhost:5500",
            "http://127.0.0.1:5500",
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "X-API-Key",
            "X-CSRF-Token",
        ],
        expose_headers=[
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ],
        max_age=600,  # Cache preflight for 10 minutes
    )

    # Trusted hosts
    if settings.ENVIRONMENT == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[
                "cyber-global-shield.com",
                "*.cyber-global-shield.com",
                "api.cyber-global-shield.com",
            ],
        )


# =============================================================================
# Setup all middleware
# =============================================================================

def setup_middleware(app: FastAPI):
    """Configure all security middleware for the application."""
    # Order matters — outermost first

    # 1. HTTPS Redirect (before anything else)
    if settings.ENVIRONMENT == "production":
        app.add_middleware(HTTPSRedirectMiddleware)

    # 2. CORS
    configure_cors(app)

    # 3. Security Headers
    app.add_middleware(SecurityHeadersMiddleware)

    # 4. Request Logging (innermost — captures everything)
    app.add_middleware(RequestLoggingMiddleware)

    # 5. Configure structured logging
    configure_logging()

    logger.info(
        "middleware_configured",
        environment=settings.ENVIRONMENT,
        cors_origins=app.state.cors_origins if hasattr(app.state, "cors_origins") else "configured",
    )
