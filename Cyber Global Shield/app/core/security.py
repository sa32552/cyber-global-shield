"""
Security module: authentication, authorization, rate limiting, API keys.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Callable
from functools import wraps

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class InvalidTokenError(Exception):
    """Raised when token validation fails."""
    pass


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass


class TokenPayload(BaseModel):
    sub: str
    org_id: str
    role: str
    exp: datetime
    iat: datetime


class User(BaseModel):
    id: str
    email: str
    org_id: str
    role: str
    permissions: list[str] = []


# ─── In-memory rate limiter (token bucket) ──────────────────────────────

class TokenBucketRateLimiter:
    """
    Token bucket rate limiter per IP address.
    Thread-safe for async usage.
    """

    def __init__(self, rate_per_second: int = 10, burst: int = 20):
        self.rate_per_second = rate_per_second
        self.burst = burst
        self._buckets: Dict[str, Dict[str, float]] = {}

    def _get_bucket(self, key: str) -> Dict[str, float]:
        now = datetime.now(timezone.utc).timestamp()
        if key not in self._buckets:
            self._buckets[key] = {"tokens": float(self.burst), "last_refill": now}
            return self._buckets[key]

        bucket = self._buckets[key]
        elapsed = now - bucket["last_refill"]
        # Refill tokens based on elapsed time
        refill = elapsed * self.rate_per_second
        bucket["tokens"] = min(float(self.burst), bucket["tokens"] + refill)
        bucket["last_refill"] = now
        return bucket

    def check(self, key: str, cost: int = 1) -> bool:
        """Check if request is allowed. Returns True if allowed."""
        bucket = self._get_bucket(key)
        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True
        return False

    def get_remaining(self, key: str) -> int:
        """Get remaining tokens for a key."""
        bucket = self._get_bucket(key)
        return int(bucket["tokens"])

    def reset(self, key: str):
        """Reset rate limit for a key."""
        self._buckets.pop(key, None)


# Global rate limiter instances
login_limiter = TokenBucketRateLimiter(rate_per_second=5, burst=10)       # 5 req/s, burst 10
api_limiter = TokenBucketRateLimiter(
    rate_per_second=settings.RATE_LIMIT_PER_SECOND,
    burst=settings.RATE_LIMIT_BURST,
)


def rate_limit(limiter: TokenBucketRateLimiter, cost: int = 1):
    """
    Decorator for rate limiting FastAPI endpoints.
    Uses client IP as the rate limit key.

    Usage:
        @router.post("/login")
        @rate_limit(login_limiter, cost=1)
        async def login(request: Request, ...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from kwargs or args
            request = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                # Fallback: no request context, allow through
                return await func(*args, **kwargs)

            client_ip = request.client.host if request.client else "unknown"
            if not limiter.check(client_ip, cost=cost):
                logger.warning("rate_limit_exceeded", ip=client_ip, limiter=limiter.__class__.__name__)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests. Please try again later.",
                        "retry_after_seconds": 1,
                    },
                    headers={
                        "Retry-After": "1",
                        "X-RateLimit-Limit": str(limiter.rate_per_second),
                        "X-RateLimit-Remaining": str(limiter.get_remaining(client_ip)),
                    },
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ─── Password utilities ─────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# ─── JWT utilities ──────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    org_id: str,
    role: str,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "sub": subject,
        "org_id": org_id,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    if extra_claims:
        to_encode.update(extra_claims)

    secret_key = settings.SECRET_KEY.get_secret_value() if hasattr(settings.SECRET_KEY, 'get_secret_value') else str(settings.SECRET_KEY)
    return jwt.encode(to_encode, secret_key, algorithm=settings.ALGORITHM)


def verify_token(token: str) -> TokenPayload:
    try:
        secret_key = settings.SECRET_KEY.get_secret_value() if hasattr(settings.SECRET_KEY, 'get_secret_value') else str(settings.SECRET_KEY)
        payload = jwt.decode(
            token, secret_key, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(
            sub=payload.get("sub", ""),
            org_id=payload.get("org_id", ""),
            role=payload.get("role", "analyst"),
            exp=payload.get("exp"),
            iat=payload.get("iat"),
        )
        return token_data
    except JWTError as e:
        raise InvalidTokenError(f"Could not validate credentials: {str(e)}")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    token_data = verify_token(token)
    user = User(
        id=token_data.sub,
        email=f"{token_data.sub}@cybershield.io",
        org_id=token_data.org_id,
        role=token_data.role,
    )
    return user


def require_role(*roles: str):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user.role} not allowed. Required: {roles}",
            )
        return current_user

    return role_checker


def generate_api_key(org_id: str, role: str = "analyst") -> str:
    return create_access_token(
        subject=org_id,
        org_id=org_id,
        role=role,
        expires_delta=timedelta(days=365),
    )
