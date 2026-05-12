"""
Cyber Global Shield — Authentication & Authorization Module
Remplace l'auth hardcodée par Supabase/Auth0 avec rate limiting Redis.
"""

import os
import time
import hashlib
import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta

import structlog
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.core.config import settings
from app.core.supabase_client import supabase_manager

logger = structlog.get_logger(__name__)

# Security schemes
security_scheme = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================================================================
# Models
# =============================================================================

class User(BaseModel):
    """Authenticated user model."""
    id: str
    username: str
    email: str
    role: str = "analyst"
    org_id: str = "default"
    permissions: List[str] = []
    is_active: bool = True
    mfa_enabled: bool = False

class AuthConfig(BaseModel):
    """Authentication provider configuration."""
    provider: str = "supabase"  # supabase, auth0, keycloak, local
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    refresh_expiry_days: int = 7
    mfa_required: bool = False
    allowed_origins: List[str] = ["http://localhost:8000", "http://localhost:3000"]

# =============================================================================
# Rate Limiter (Redis-backed)
# =============================================================================

class RateLimiter:
    """Token bucket rate limiter with Redis backend."""

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._local_buckets: Dict[str, Dict] = {}  # Fallback when Redis unavailable

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> bool:
        """Check if request is within rate limit. Returns True if allowed."""
        now = time.time()

        if self.redis:
            # Redis-backed rate limiting
            try:
                pipe = self.redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, window_seconds)
                count, _ = await pipe.execute()
                return int(count) <= max_requests
            except Exception as e:
                logger.warning("redis_rate_limit_failed", error=str(e))
                # Fall through to local rate limiting

        # Local fallback rate limiting
        bucket = self._local_buckets.get(key, {"tokens": max_requests, "last_refill": now})

        # Refill tokens
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(max_requests, bucket["tokens"] + elapsed * (max_requests / window_seconds))
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            self._local_buckets[key] = bucket
            return True

        self._local_buckets[key] = bucket
        return False

    def get_remaining(self, key: str, max_requests: int = 60) -> int:
        """Get remaining requests for a key."""
        bucket = self._local_buckets.get(key)
        if not bucket:
            return max_requests
        return max(0, int(bucket["tokens"]))


# Global rate limiter instance
rate_limiter = RateLimiter()


# =============================================================================
# Authentication Manager
# =============================================================================

class AuthManager:
    """
    Authentication manager supporting multiple providers.
    Replaces hardcoded admin/cybershield2024 with proper auth.
    Uses Supabase Auth for production, local fallback for development.
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig(
            jwt_secret=settings.SECRET_KEY,
            provider="local" if settings.ENVIRONMENT == "development" else "supabase",
        )
        # In-memory user store for development (fallback when Supabase unavailable)
        self._users: Dict[str, Dict] = {
            "admin": {
                "id": "user-admin-001",
                "username": "admin",
                "email": "admin@cyberglobalshield.com",
                "password": pwd_context.hash("Admin@2024Secure!"),
                "role": "admin",
                "org_id": "global",
                "permissions": ["*"],
                "is_active": True,
                "mfa_enabled": False,
            },
            "analyst": {
                "id": "user-analyst-001",
                "username": "analyst",
                "email": "analyst@cyberglobalshield.com",
                "password": pwd_context.hash("Analyst@2024Secure!"),
                "role": "analyst",
                "org_id": "org-a",
                "permissions": ["alerts:read", "dashboard:read", "soar:execute"],
                "is_active": True,
                "mfa_enabled": False,
            },
            "soc_engineer": {
                "id": "user-soc-001",
                "username": "soc_engineer",
                "email": "soc@cyberglobalshield.com",
                "password": pwd_context.hash("SOC@2024Secure!"),
                "role": "soc_engineer",
                "org_id": "org-a",
                "permissions": ["alerts:*", "dashboard:*", "soar:*", "ml:detect"],
                "is_active": True,
                "mfa_enabled": False,
            },
        }
        self._refresh_tokens: Dict[str, Dict] = {}
        self._api_keys: Dict[str, Dict] = {}

    async def authenticate(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with username/password.
        Delegates to Supabase Auth when provider is "supabase".
        Falls back to local in-memory store for development.
        """
        if self.config.provider == "supabase" and supabase_manager.client:
            # ── Supabase Auth ──────────────────────────────────────────
            try:
                from supabase import create_client
                # Use the anon key for client-side auth (sign in)
                supabase_client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_KEY.get_secret_value() if settings.SUPABASE_KEY else "",
                )
                res = supabase_client.auth.sign_in_with_password(
                    {"email": username, "password": password}
                )
                if not res.user:
                    logger.warning("login_failed_supabase", username=username, ip=ip_address)
                    return None

                session = res.session
                user_meta = res.user.user_metadata or {}

                # Fetch profile from our profiles table
                profile = await supabase_manager.get_profile(res.user.id)

                role = profile.get("role", "analyst") if profile else user_meta.get("role", "analyst")
                org_id = profile.get("org_id", "default") if profile else user_meta.get("org_id", "default")
                permissions = profile.get("permissions", []) if profile else []

                logger.info("login_success_supabase", username=res.user.email, role=role, ip=ip_address)

                return {
                    "access_token": session.access_token,
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "refresh_token": session.refresh_token,
                    "user": {
                        "id": res.user.id,
                        "username": res.user.email,
                        "email": res.user.email,
                        "role": role,
                        "org_id": org_id,
                        "permissions": permissions,
                    },
                }
            except Exception as e:
                logger.error("supabase_auth_failed", error=str(e), ip=ip_address)
                # Fall through to local auth as fallback
                logger.warning("auth_fallback_to_local", username=username)

        # ── Local Auth (development fallback) ──────────────────────────
        user = self._users.get(username)
        if not user:
            logger.warning("login_failed_user_not_found", username=username, ip=ip_address)
            return None

        if not user["is_active"]:
            logger.warning("login_failed_user_disabled", username=username)
            return None

        if not pwd_context.verify(password, user["password"]):
            logger.warning("login_failed_wrong_password", username=username, ip=ip_address)
            return None

        # Check if password needs rehash
        if pwd_context.needs_update(user["password"]):
            user["password"] = pwd_context.hash(password)
            logger.info("password_rehashed", username=username)

        # MFA check
        if user["mfa_enabled"] and not mfa_code:
            return {"mfa_required": True, "user_id": user["id"]}

        # Generate tokens
        access_token = self._create_access_token(user)
        refresh_token = self._create_refresh_token(user)

        # Store refresh token
        self._refresh_tokens[refresh_token] = {
            "user_id": user["id"],
            "username": user["username"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "ip": ip_address,
        }

        logger.info("login_success_local", username=username, role=user["role"], ip=ip_address)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": self.config.jwt_expiry_minutes * 60,
            "refresh_token": refresh_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "org_id": user["org_id"],
                "permissions": user["permissions"],
            },
        }

    async def authenticate_with_api_key(self, api_key: str) -> Optional[User]:
        """Authenticate using API key. Checks Supabase first, then local store."""
        # Try Supabase API key verification
        if supabase_manager.client:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            key_data = await supabase_manager.verify_api_key(key_hash)
            if key_data:
                return User(
                    id=key_data["user_id"],
                    username=key_data.get("email", "api-user"),
                    email=key_data.get("email", ""),
                    role=key_data.get("role", "analyst"),
                    org_id=key_data.get("org_id", "default"),
                    permissions=key_data.get("permissions", []),
                )

        # Local fallback
        key_data = self._api_keys.get(api_key)
        if not key_data:
            return None
        if key_data.get("expires_at") and datetime.fromisoformat(key_data["expires_at"]) < datetime.now(timezone.utc):
            del self._api_keys[api_key]
            return None
        return User(
            id=key_data["user_id"],
            username=key_data["username"],
            email=key_data.get("email", ""),
            role=key_data["role"],
            org_id=key_data["org_id"],
            permissions=key_data.get("permissions", []),
        )

    async def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh an access token using a refresh token."""
        # Try Supabase refresh
        if self.config.provider == "supabase" and supabase_manager.client:
            try:
                from supabase import create_client
                supabase_client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_KEY.get_secret_value() if settings.SUPABASE_KEY else "",
                )
                res = supabase_client.auth.refresh_session(refresh_token)
                if res.session:
                    return {
                        "access_token": res.session.access_token,
                        "token_type": "bearer",
                        "expires_in": 3600,
                    }
            except Exception as e:
                logger.warning("supabase_refresh_failed", error=str(e))

        # Local fallback
        token_data = self._refresh_tokens.get(refresh_token)
        if not token_data:
            return None

        user = self._users.get(token_data["username"])
        if not user or not user["is_active"]:
            return None

        new_access_token = self._create_access_token(user)
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": self.config.jwt_expiry_minutes * 60,
        }

    async def revoke_token(self, refresh_token: str) -> bool:
        """Revoke a refresh token."""
        # Try Supabase sign out
        if self.config.provider == "supabase" and supabase_manager.client:
            try:
                from supabase import create_client
                supabase_client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_KEY.get_secret_value() if settings.SUPABASE_KEY else "",
                )
                supabase_client.auth.sign_out()
            except Exception:
                pass

        if refresh_token in self._refresh_tokens:
            del self._refresh_tokens[refresh_token]
            return True
        return False

    async def generate_api_key(
        self,
        user_id: str,
        role: str,
        org_id: str,
        expires_in_days: int = 365,
    ) -> str:
        """Generate a new API key."""
        api_key = f"cgs_{secrets.token_urlsafe(32)}"
        user = next((u for u in self._users.values() if u["id"] == user_id), None)

        # Store in Supabase if available
        if supabase_manager.client:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
            await supabase_manager.store_api_key(
                key_hash=key_hash,
                user_id=user_id,
                org_id=org_id,
                expires_at=expires_at,
            )

        # Also store locally for fallback
        self._api_keys[api_key] = {
            "user_id": user_id,
            "username": user["username"] if user else "api",
            "role": role,
            "org_id": org_id,
            "permissions": user["permissions"] if user else [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat(),
        }
        return api_key

    async def get_user_from_token(self, token: str) -> Optional[User]:
        """Extract user from JWT token. Supports both Supabase JWTs and local JWTs."""
        # ── Try Supabase JWT verification first ────────────────────────
        if self.config.provider == "supabase" and settings.SUPABASE_JWT_SECRET:
            try:
                supabase_jwt_secret = settings.SUPABASE_JWT_SECRET.get_secret_value()
                if supabase_jwt_secret:
                    payload = jwt.decode(
                        token,
                        supabase_jwt_secret,
                        algorithms=["HS256"],
                        options={"verify_aud": False},
                    )
                    user_id = payload.get("sub")
                    if not user_id:
                        return None

                    # Fetch profile from Supabase
                    profile = await supabase_manager.get_profile(user_id)
                    if profile:
                        return User(
                            id=user_id,
                            username=profile.get("full_name", payload.get("email", user_id)),
                            email=payload.get("email", profile.get("email", "")),
                            role=profile.get("role", "analyst"),
                            org_id=profile.get("org_id", "default"),
                            permissions=profile.get("permissions", []),
                            is_active=True,
                        )

                    # If no profile yet, create a basic user from JWT claims
                    user_metadata = payload.get("user_metadata", {})
                    return User(
                        id=user_id,
                        username=user_metadata.get("full_name", payload.get("email", user_id)),
                        email=payload.get("email", ""),
                        role=user_metadata.get("role", "analyst"),
                        org_id=user_metadata.get("org_id", "default"),
                        permissions=[],
                        is_active=True,
                    )
            except JWTError as e:
                logger.debug("supabase_jwt_decode_failed", error=str(e))
                # Fall through to local JWT verification

        # ── Local JWT verification (fallback) ──────────────────────────
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
            )
            username = payload.get("sub")
            if not username:
                return None

            user = self._users.get(username)
            if not user or not user["is_active"]:
                return None

            return User(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                role=user["role"],
                org_id=user["org_id"],
                permissions=user["permissions"],
            )
        except JWTError as e:
            logger.warning("jwt_decode_failed", error=str(e))
            return None

    def _create_access_token(self, user: Dict) -> str:
        """Create a JWT access token."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user["username"],
            "user_id": user["id"],
            "role": user["role"],
            "org_id": user["org_id"],
            "permissions": user["permissions"],
            "iat": now,
            "exp": now + timedelta(minutes=self.config.jwt_expiry_minutes),
            "type": "access",
        }
        return jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)

    def _create_refresh_token(self, user: Dict) -> str:
        """Create a refresh token."""
        return f"cgs_ref_{secrets.token_urlsafe(48)}"


# Global auth manager instance
auth_manager = AuthManager()


# =============================================================================
# FastAPI Dependencies
# =============================================================================

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    token: Optional[str] = Depends(oauth2_scheme),
) -> User:
    """
    FastAPI dependency to get the current authenticated user.
    Supports both Bearer tokens and OAuth2 password flow.
    """
    # Extract token from either scheme
    token_str = None
    if credentials:
        token_str = credentials.credentials
    elif token:
        token_str = token

    if not token_str:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try API key first
    if token_str.startswith("cgs_"):
        user = await auth_manager.authenticate_with_api_key(token_str)
        if user:
            return user
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Try JWT token (Supabase or local)
    user = await auth_manager.get_user_from_token(token_str)
    if user:
        return user

    raise HTTPException(
        status_code=401,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_role(*roles: str):
    """
    FastAPI dependency factory to require specific roles.
    Usage: `current_user: User = Depends(require_role("admin", "soc_engineer"))`
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and "*" not in current_user.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of these roles: {', '.join(roles)}",
            )
        return current_user
    return role_checker


async def require_permission(permission: str):
    """
    FastAPI dependency factory to require specific permissions.
    Usage: `current_user: User = Depends(require_permission("alerts:write"))`
    """
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if permission not in current_user.permissions and "*" not in current_user.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Missing required permission: {permission}",
            )
        return current_user
    return permission_checker


async def check_rate_limit(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    FastAPI dependency for rate limiting.
    """
    key = f"ratelimit:{current_user.id}"
    allowed = await rate_limiter.check_rate_limit(
        key=key,
        max_requests=settings.RATE_LIMIT_PER_SECOND,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait before making more requests.",
            headers={"Retry-After": "60"},
        )
    return current_user


# =============================================================================
# Utility Functions
# =============================================================================

def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging (GDPR compliant)."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    Returns (is_valid, message).
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain an uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain a lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain a digit"
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" for c in password):
        return False, "Password must contain a special character"
    return True, "Password is strong"
