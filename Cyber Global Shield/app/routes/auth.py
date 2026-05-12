"""
Cyber Global Shield v2.0 — Authentication Endpoints
Supports Supabase Auth (production) and local auth (development).
"""

from datetime import timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import structlog

from app.core.config import settings
from app.core.security import (
    create_access_token,
    get_current_user,
    User,
    require_role,
    generate_api_key,
    rate_limit,
    login_limiter,
)
from app.core.auth import auth_manager, validate_password_strength
from app.core.supabase_client import supabase_manager

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str = ""
    org_name: str = ""
    role: str = "analyst"


class APIKeyRequest(BaseModel):
    org_id: str
    role: str = "analyst"


@router.post("/login")
@rate_limit(login_limiter, cost=1)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
):
    """
    Authenticate and get access token.
    Uses Supabase Auth in production, local auth in development.
    """
    ip_address = request.client.host if request and request.client else None

    # Delegate to AuthManager which handles Supabase or local auth
    result = await auth_manager.authenticate(
        username=form_data.username,
        password=form_data.password,
        ip_address=ip_address,
    )

    if result:
        return result

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )


@router.post("/register")
@rate_limit(login_limiter, cost=2)
async def register(
    data: RegisterRequest,
    request: Request = None,
):
    """
    Register a new user via Supabase Auth.
    Creates the auth user, an organization, and a profile.
    """
    # Validate password strength
    is_valid, msg = validate_password_strength(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    if not supabase_manager.client:
        raise HTTPException(
            status_code=503,
            detail="Supabase is not configured. Registration is only available in production mode.",
        )

    try:
        # 1. Create organization (or use default)
        org_id = "default"
        if data.org_name:
            slug = data.org_name.lower().replace(" ", "-")
            org = await supabase_manager.get_organization_by_slug(slug)
            if not org:
                org = await supabase_manager.create_organization(
                    name=data.org_name,
                    slug=slug,
                    tier="free",
                )
            if org:
                org_id = org["id"]

        # 2. Create user in Supabase Auth
        user = await supabase_manager.create_user(
            email=data.email,
            password=data.password,
            user_metadata={
                "full_name": data.full_name,
                "role": data.role,
                "org_id": org_id,
            },
        )
        if not user:
            raise HTTPException(status_code=400, detail="User registration failed")

        # 3. Create profile in our profiles table
        await supabase_manager.create_profile(
            user_id=user["id"],
            org_id=org_id,
            full_name=data.full_name,
            role=data.role,
        )

        logger.info("user_registered", email=data.email, org_id=org_id, role=data.role)

        return {
            "id": user["id"],
            "email": user["email"],
            "org_id": org_id,
            "role": data.role,
            "message": "User registered successfully. Check your email for confirmation.",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("registration_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/api-key")
async def generate_api_key_endpoint(
    request: APIKeyRequest,
    current_user: User = Depends(get_current_user),
):
    """Generate an API key for programmatic access."""
    api_key = await auth_manager.generate_api_key(
        user_id=current_user.id,
        role=request.role,
        org_id=request.org_id,
    )
    return {"api_key": api_key, "org_id": request.org_id, "role": request.role}


@router.post("/refresh")
async def refresh_token(refresh_token: str):
    """Refresh an access token using a refresh token."""
    result = await auth_manager.refresh_access_token(refresh_token)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    return result


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout and revoke the current session."""
    # Supabase handles session invalidation on the client side
    # We just acknowledge the logout
    logger.info("user_logged_out", user_id=current_user.id, username=current_user.username)
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "permissions": current_user.permissions,
    }
