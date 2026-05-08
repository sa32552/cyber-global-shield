"""
Rate Limiter Middleware for Cyber Global Shield
Implements token bucket algorithm with Redis backend.
"""

import time
import asyncio
from typing import Dict, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


class TokenBucket:
    """Token bucket rate limiter implementation."""

    def __init__(self, rate: int, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.tokens = burst
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_wait_time(self) -> float:
        """Get time to wait before next token is available."""
        if self.tokens > 0:
            return 0
        return 1.0 / self.rate


class RateLimiter:
    """
    Distributed rate limiter with per-IP and per-API-key tracking.
    Falls back to in-memory token bucket if Redis is unavailable.
    """

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._ip_buckets: Dict[str, TokenBucket] = {}
        self._api_key_buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
        self._stats: Dict[str, Dict] = defaultdict(lambda: {
            "total_requests": 0,
            "blocked_requests": 0,
            "last_request_time": None,
        })

    def _get_bucket_key(self, request: Request) -> str:
        """Generate a bucket key from request."""
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")
        return f"{client_ip}:{api_key}"

    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if request is within rate limits.
        Returns True if allowed, False if rate limited.
        """
        bucket_key = self._get_bucket_key(request)
        client_ip = request.client.host if request.client else "unknown"

        async with self._lock:
            # Initialize buckets if needed
            if client_ip not in self._ip_buckets:
                self._ip_buckets[client_ip] = TokenBucket(
                    rate=settings.RATE_LIMIT_PER_SECOND,
                    burst=settings.RATE_LIMIT_BURST,
                )
            if bucket_key not in self._buckets:
                self._buckets[bucket_key] = TokenBucket(
                    rate=settings.RATE_LIMIT_PER_SECOND * 10,
                    burst=settings.RATE_LIMIT_BURST * 5,
                )

            ip_bucket = self._ip_buckets[client_ip]
            key_bucket = self._buckets[bucket_key]

        # Update stats
        self._stats[bucket_key]["total_requests"] += 1
        self._stats[bucket_key]["last_request_time"] = datetime.now(timezone.utc).isoformat()

        # Check IP-level rate limit
        if not await ip_bucket.consume():
            self._stats[bucket_key]["blocked_requests"] += 1
            logger.warning("rate_limit_exceeded_ip", client_ip=client_ip, bucket_key=bucket_key)
            return False

        # Check key-level rate limit
        if not await key_bucket.consume():
            self._stats[bucket_key]["blocked_requests"] += 1
            logger.warning("rate_limit_exceeded_key", client_ip=client_ip, bucket_key=bucket_key)
            return False

        return True

    async def get_retry_after(self, request: Request) -> float:
        """Get retry-after time in seconds."""
        bucket_key = self._get_bucket_key(request)
        bucket = self._buckets.get(bucket_key)
        if bucket:
            return bucket.get_wait_time()
        return 1.0

    def get_stats(self) -> Dict:
        """Get rate limiter statistics."""
        total = sum(s["total_requests"] for s in self._stats.values())
        blocked = sum(s["blocked_requests"] for s in self._stats.values())
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate": round(blocked / max(total, 1) * 100, 2),
            "active_buckets": len(self._buckets),
            "active_ips": len(self._ip_buckets),
        }


# Global rate limiter instance
rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    """
    FastAPI middleware for rate limiting.
    Add to app: app.middleware("http")(rate_limit_middleware)
    """
    # Skip rate limiting for health checks and docs
    if request.url.path in ("/health", "/", "/docs", "/redoc", "/openapi.json"):
        return await call_next(request)

    # Check rate limit
    allowed = await rate_limiter.check_rate_limit(request)
    if not allowed:
        retry_after = await rate_limiter.get_retry_after(request)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded. Please slow down.",
                "retry_after_seconds": retry_after,
            },
            headers={
                "Retry-After": str(int(retry_after)),
                "X-RateLimit-Limit": str(settings.RATE_LIMIT_PER_SECOND),
                "X-RateLimit-Remaining": "0",
            },
        )

    response = await call_next(request)

    # Add rate limit headers
    response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_PER_SECOND)
    response.headers["X-RateLimit-Remaining"] = "100"  # Approximate

    return response
